// VLESS-only Cloudflare Worker
// Scope: VLESS over WebSocket, TCP outbound, optional WebSocket early data.
// TLS/WSS is terminated by Cloudflare at the edge; this Worker handles the
// resulting WebSocket request. Configure UUID and PATH as Worker variables.

import { connect } from 'cloudflare:sockets';

const DEFAULT_PATH = '/';
const MAX_HEADER_BYTES = 64 * 1024;
const MAX_EARLY_DATA_BYTES = 8 * 1024;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const configuredPath = normalizePath(env.PATH || DEFAULT_PATH);
    const requestPath = normalizePath(url.pathname);
    const expectedUUID = normalizeUUID(env.UUID || env.uuid || '');

    if (!expectedUUID) {
      return new Response('Missing valid UUID configuration', { status: 500 });
    }

    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', {
        status: 405,
        headers: { Allow: 'GET' },
      });
    }

    if (requestPath !== configuredPath) {
      return new Response('Not Found', { status: 404 });
    }

    if ((request.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
      return new Response('VLESS WebSocket endpoint', {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    return handleWebSocket(request, expectedUUID);
  },
};

async function handleWebSocket(request, expectedUUID) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];

  server.accept();
  server.binaryType = 'arraybuffer';

  const state = {
    headerBuffer: new Uint8Array(0),
    remote: null,
    remoteWriter: null,
    requestParsed: false,
    closed: false,
    writeChain: Promise.resolve(),
    processingChain: Promise.resolve(),
    earlyDataConsumed: false,
  };

  const close = async (reason) => {
    if (state.closed) return;
    state.closed = true;
    try { state.remoteWriter?.releaseLock(); } catch (_) {}
    try { await state.remote?.close?.(); } catch (_) {}
    try { server.close(1000, reason ? String(reason).slice(0, 120) : 'closed'); } catch (_) {}
  };

  const queueRemoteWrite = (bytes) => {
    if (!bytes?.byteLength || state.closed) return state.writeChain;
    state.writeChain = state.writeChain
      .then(async () => {
        if (state.closed || !state.remote) return;
        if (!state.remoteWriter) state.remoteWriter = state.remote.writable.getWriter();
        await state.remoteWriter.write(bytes);
      })
      .catch(close);
    return state.writeChain;
  };

  const sendToClient = (bytes) => {
    if (state.closed || !bytes?.byteLength) return;
    try { server.send(bytes); } catch (_) { void close('send failed'); }
  };

  const startDownlink = async (version) => {
    const reader = state.remote.readable.getReader();
    let sentResponseHeader = false;
    try {
      while (!state.closed) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = toUint8Array(value);
        if (!chunk.byteLength) continue;
        if (!sentResponseHeader) {
          sendToClient(concatBytes(new Uint8Array([version, 0]), chunk));
          sentResponseHeader = true;
        } else {
          sendToClient(chunk);
        }
      }
    } finally {
      try { reader.releaseLock(); } catch (_) {}
      await close('remote closed');
    }
  };

  const parseAndConnect = async (bytes) => {
    state.headerBuffer = concatBytes(state.headerBuffer, bytes);
    if (state.headerBuffer.byteLength > MAX_HEADER_BYTES) {
      throw new Error('VLESS header too large');
    }

    const parsed = parseVlessHeader(state.headerBuffer, expectedUUID);
    if (parsed.status === 'incomplete') return;
    if (parsed.status === 'invalid') throw new Error(parsed.message);
    if (parsed.command !== 1) {
      throw new Error('Only VLESS TCP is enabled in this clean Worker');
    }

    state.requestParsed = true;
    const remote = connect({
      hostname: parsed.hostname,
      port: parsed.port,
    });
    state.remote = remote;
    await remote.opened;

    // Start reading before writing the first payload so fast remote responses
    // are not delayed by the initial client write.
    void startDownlink(parsed.version);
    await queueRemoteWrite(parsed.payload);
    state.headerBuffer = new Uint8Array(0);
  };

  const processMessage = async (data) => {
    if (state.closed) return;
    const bytes = toUint8Array(data);
    if (!bytes.byteLength) return;

    if (!state.requestParsed) {
      await parseAndConnect(bytes);
      return;
    }

    await queueRemoteWrite(bytes);
  };

  server.addEventListener('message', (event) => {
    state.processingChain = state.processingChain
      .then(() => processMessage(event.data))
      .catch((error) => close(error?.message || 'invalid VLESS request'));
  });

  server.addEventListener('close', () => { void close('client closed'); });
  server.addEventListener('error', () => { void close('websocket error'); });

  // Xray-compatible WebSocket early data is carried in
  // Sec-WebSocket-Protocol as URL-safe base64. It is accepted only when it
  // already forms a valid VLESS header; otherwise the normal first message
  // path is used.
  const earlyHeader = request.headers.get('Sec-WebSocket-Protocol');
  const earlyData = decodeEarlyData(earlyHeader);
  if (earlyData?.byteLength) {
    state.earlyDataConsumed = true;
    state.processingChain = state.processingChain
      .then(() => processMessage(earlyData))
      .catch((error) => close(error?.message || 'invalid early VLESS request'));
  }

  return new Response(null, {
    status: 101,
    webSocket: client,
    headers: { 'Sec-WebSocket-Extensions': '' },
  });
}

function parseVlessHeader(input, expectedUUID) {
  const data = toUint8Array(input);
  if (data.byteLength < 18) return { status: 'incomplete' };

  if (!uuidBytesMatch(data, 1, expectedUUID)) {
    return { status: 'invalid', message: 'Invalid VLESS UUID' };
  }

  const optionsLength = data[17];
  const commandIndex = 18 + optionsLength;
  if (data.byteLength < commandIndex + 4) return { status: 'incomplete' };

  const command = data[commandIndex];
  const port = (data[commandIndex + 1] << 8) | data[commandIndex + 2];
  const addressType = data[commandIndex + 3];
  let cursor = commandIndex + 4;
  let hostname;

  if (addressType === 1) {
    if (data.byteLength < cursor + 4) return { status: 'incomplete' };
    hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
    cursor += 4;
  } else if (addressType === 2) {
    if (data.byteLength < cursor + 1) return { status: 'incomplete' };
    const length = data[cursor++];
    if (data.byteLength < cursor + length) return { status: 'incomplete' };
    hostname = new TextDecoder().decode(data.subarray(cursor, cursor + length));
    cursor += length;
  } else if (addressType === 3) {
    if (data.byteLength < cursor + 16) return { status: 'incomplete' };
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((data[cursor + i * 2] << 8) | data[cursor + i * 2 + 1]).toString(16));
    }
    hostname = parts.join(':');
    cursor += 16;
  } else {
    return { status: 'invalid', message: `Unsupported VLESS address type: ${addressType}` };
  }

  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    return { status: 'invalid', message: 'Invalid VLESS destination' };
  }

  return {
    status: 'ok',
    version: data[0],
    command,
    hostname,
    port,
    payload: data.subarray(cursor),
  };
}

function normalizeUUID(value) {
  const uuid = String(value).trim().toLowerCase();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)
    ? uuid
    : '';
}

function uuidBytes(uuid) {
  const hex = uuid.replaceAll('-', '');
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return result;
}

function uuidBytesMatch(data, offset, uuid) {
  const expected = uuidBytes(uuid);
  if (data.byteLength < offset + 16) return false;
  for (let i = 0; i < 16; i++) {
    if (data[offset + i] !== expected[i]) return false;
  }
  return true;
}

function decodeEarlyData(value) {
  if (!value || value.length > Math.ceil(MAX_EARLY_DATA_BYTES * 4 / 3) + 8) return null;
  const candidates = String(value).split(',').map((part) => part.trim()).filter(Boolean);
  for (const candidate of candidates) {
    try {
      const normalized = candidate.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(candidate.length / 4) * 4, '=');
      const binary = atob(normalized);
      if (binary.length > MAX_EARLY_DATA_BYTES) continue;
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      if (bytes.byteLength >= 18) return bytes;
    } catch (_) {}
  }
  return null;
}

function normalizePath(path) {
  const value = String(path || '/').trim();
  if (!value || value === '/') return '/';
  return `/${value.replace(/^\/+|\/+$/g, '')}`;
}

function toUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return new Uint8Array(0);
}

function concatBytes(...parts) {
  const arrays = parts.map(toUint8Array);
  const total = arrays.reduce((sum, part) => sum + part.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of arrays) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}
