// server.js
const express = require('express');
const net = require('net');
const tls = require('tls');
const http = require('http');
const path = require('path');
const fs = require('fs');

const { extractSNI, isCompleteClientHello } = require('./sni');
const { parseVlessHeader, isValidUUID } = require('./vless');
const { parseVlessUrl, buildVlessUrl, buildSpoofedConfig } = require('./config');
const { isFakeDomain, getSpoofContext } = require('./spoof');
const { getState, updateState } = require('./state');

const PORT = parseInt(process.env.PORT || '3000', 10);

// نقشه‌ی uuid → کانفیگ اصلی (upstream واقعی)
const uuidToConfig = new Map();

// ==================== Express ====================

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => {
  res.type('html').send(fs.readFileSync(path.join(__dirname, 'panel.html'), 'utf8'));
});

app.get('/api/state', (req, res) => {
  res.json(getState());
});

app.post('/api/state', (req, res) => {
  const next = updateState(req.body || {});
  res.json({ ok: true, state: next });
});

app.post('/api/spoof', async (req, res) => {
  try {
    const { url, fakeDomain, publicHost, tlsEnabled, wsPath } = req.body;
    if (!url) return res.status(400).json({ ok: false, error: 'url required' });
    if (!fakeDomain) return res.status(400).json({ ok: false, error: 'fakeDomain required' });
    if (!publicHost) return res.status(400).json({ ok: false, error: 'publicHost required' });

    const st = getState();
    const fakeLower = String(fakeDomain).toLowerCase();

    if (!st.fakeDomains.includes(fakeLower)) {
      return res.status(400).json({
        ok: false,
        error: `domain not allowed: ${fakeDomain}`,
        allowed: st.fakeDomains,
      });
    }

    const original = parseVlessUrl(url.trim());
    if (!isValidUUID(original.uuid)) {
      return res.status(400).json({ ok: false, error: 'invalid uuid' });
    }

    // ثبت mapping برای relay
    uuidToConfig.set(original.uuid.toLowerCase(), {
      host: original.host,
      port: original.port || 443,
      sni: original.sni || original.host,
      path: original.path || '/',
      hostHeader: original.host_header || original.host,
      registeredAt: Date.now(),
    });

    console.log(`[map] uuid=${original.uuid} → ${original.host}:${original.port}`);

    const useTls = typeof tlsEnabled === 'boolean' ? tlsEnabled : st.tlsEnabled;

    let pinnedFingerprint = '';
    if (useTls) {
      try {
        const ctx = await getSpoofContext(fakeLower);
        pinnedFingerprint = ctx.fingerprint || '';
        console.log(`[spoof] fingerprint for ${fakeLower}: ${pinnedFingerprint}`);
      } catch (e) {
        console.error(`[spoof] cert error:`, e.message);
        return res.status(500).json({ ok: false, error: `cert error: ${e.message}` });
      }
    }

    const spoofed = buildSpoofedConfig(original, {
      fakeDomain: fakeLower,
      publicHost,
      publicPort: 443,
      path: wsPath || original.path || st.defaultWsPath,
      uuid: original.uuid,
      tlsEnabled: useTls,
      pinnedPeerCertSha256: pinnedFingerprint,
    });

    res.json({
      ok: true,
      original,
      spoofed,
      url: buildVlessUrl(spoofed),
      fingerprint: pinnedFingerprint,
    });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), mappings: uuidToConfig.size });
});

// ==================== HTTP + Raw TCP ====================

const httpServer = http.createServer(app);

const rawServer = net.createServer((socket) => {
  socket.once('data', (chunk) => {
    if (chunk.length === 0) return socket.destroy();
    if (chunk[0] === 0x16) {
      handleTLSConnection(socket, chunk);
    } else {
      httpServer.emit('connection', socket);
      socket.unshift(chunk);
    }
  });
  socket.on('error', () => {});
});

rawServer.listen(PORT, () => {
  const st = getState();
  console.log(`[raw] listening on ${PORT}`);
  console.log(`[ghostsni] fake domains: ${st.fakeDomains.join(', ')}`);
});

// ==================== TLS Handler ====================

function handleTLSConnection(socket, firstChunk) {
  let buffer = firstChunk;
  let done = false;

  const onData = async (chunk) => {
    if (done) return;
    buffer = Buffer.concat([buffer, chunk]);

    if (!isCompleteClientHello(buffer)) return;
    done = true;
    socket.removeListener('data', onData);

    const sni = extractSNI(buffer);
    if (!sni) return socket.destroy();

    console.log(`[tls] SNI=${sni}`);

    const st = getState();

    if (!isFakeDomain(sni)) {
      if (st.fakeResponse) {
        console.log(`[tls] ${sni} not allowed → transparent relay`);
        transparentRelay(socket, buffer, sni);
      } else {
        socket.destroy();
      }
      return;
    }

    let ctx;
    try {
      ctx = await getSpoofContext(sni);
    } catch (e) {
      console.error(`[tls] cert err ${sni}:`, e.message);
      return socket.destroy();
    }

    const tlsSocket = new tls.TLSSocket(socket, {
      isServer: true,
      cert: ctx.cert,
      key: ctx.key,
      SNICallback: (name, cb) => {
        cb(null, tls.createSecureContext({ cert: ctx.cert, key: ctx.key }));
      },
    });

    tlsSocket.on('error', (e) => {
      console.error(`[tls] secure err:`, e.message);
      try { socket.destroy(); } catch {}
    });

    tlsSocket.on('secure', () => {
      console.log(`[tls] handshake OK SNI=${sni}`);

      let vlessBuf = Buffer.alloc(0);
      let upstreamTls = null;
      let piped = false;

      const onSecureData = (data) => {
        if (piped && upstreamTls) {
          upstreamTls.write(data);
          return;
        }

        vlessBuf = Buffer.concat([vlessBuf, data]);
        const header = parseVlessHeader(vlessBuf);
        if (!header) return;

        if (!isValidUUID(header.uuid)) {
          console.log(`[vless] bad uuid`);
          return tlsSocket.destroy();
        }

        const stNow = getState();
        if (stNow.allowedUuids.length && !stNow.allowedUuids.includes(header.uuid)) {
          console.log(`[vless] uuid not allowed`);
          return tlsSocket.destroy();
        }

        const mapping = uuidToConfig.get(header.uuid.toLowerCase());
        if (!mapping) {
          console.log(`[vless] no mapping for ${header.uuid} — paste config in panel first`);
          return tlsSocket.destroy();
        }

        const upstreamHost = mapping.host;
        const upstreamPort = mapping.port || 443;
        const upstreamSni = mapping.sni || upstreamHost;

        console.log(`[relay] ${header.uuid} → ${upstreamHost}:${upstreamPort} (SNI=${upstreamSni})`);

        upstreamTls = tls.connect({
          host: upstreamHost,
          port: upstreamPort,
          servername: upstreamSni,
          rejectUnauthorized: false,
        }, () => {
          console.log(`[relay] upstream connected`);

          if (header.payload.length) {
            upstreamTls.write(header.payload);
          }

          piped = true;
          upstreamTls.pipe(tlsSocket);
          tlsSocket.pipe(upstreamTls);
        });

        upstreamTls.on('error', (e) => {
          console.error(`[relay] upstream err:`, e.message);
          try { tlsSocket.destroy(); } catch {}
        });

        upstreamTls.on('close', () => {
          try { tlsSocket.destroy(); } catch {}
        });

        tlsSocket.removeListener('data', onSecureData);
      };

      tlsSocket.on('data', onSecureData);
    });

    tlsSocket.unshift(buffer);
  };

  socket.on('data', onData);
  socket.on('error', () => {});
}

// ==================== transparent relay ====================

function transparentRelay(clientSocket, initialData, domain) {
  const upstream = tls.connect({
    host: domain,
    port: 443,
    servername: domain,
    rejectUnauthorized: false,
  }, () => {
    if (initialData && initialData.length) upstream.write(initialData);
  });

  const cleanup = () => {
    try { clientSocket.destroy(); } catch {}
    try { upstream.destroy(); } catch {}
  };

  upstream.on('error', cleanup);
  clientSocket.on('error', cleanup);
  upstream.on('close', cleanup);
  clientSocket.on('close', cleanup);

  clientSocket.pipe(upstream);
  upstream.pipe(clientSocket);

  return upstream;
}

process.on('uncaughtException', (e) => console.error('[uncaught]', e));
process.on('unhandledRejection', (e) => console.error('[unhandled]', e));
