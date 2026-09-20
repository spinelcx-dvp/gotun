// relay.js
const net = require('net');
const tls = require('tls');

function relayToUpstream(clientSocket, initialData, upstream) {
  let upstreamSocket;

  if (upstream.tls) {
    upstreamSocket = tls.connect({
      host: upstream.host,
      port: upstream.port,
      servername: upstream.sni || upstream.host,
      rejectUnauthorized: false,
    });
  } else {
    upstreamSocket = net.connect({
      host: upstream.host,
      port: upstream.port,
    });
  }

  const cleanup = () => {
    try { clientSocket.destroy(); } catch {}
    try { upstreamSocket.destroy(); } catch {}
  };

  upstreamSocket.on('connect', () => {
    if (initialData && initialData.length) upstreamSocket.write(initialData);
  });

  upstreamSocket.on('error', cleanup);
  clientSocket.on('error', cleanup);
  upstreamSocket.on('close', cleanup);
  clientSocket.on('close', cleanup);

  clientSocket.pipe(upstreamSocket);
  upstreamSocket.pipe(clientSocket);

  return upstreamSocket;
}

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

module.exports = { relayToUpstream, transparentRelay };
