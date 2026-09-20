// config.js
function parseVlessUrl(url) {
  if (!url.startsWith('vless://')) throw new Error('not a vless url');

  const withoutScheme = url.slice('vless://'.length);
  const hashIdx = withoutScheme.indexOf('#');
  const name = hashIdx >= 0 ? decodeURIComponent(withoutScheme.slice(hashIdx + 1)) : '';
  const main = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;

  const qIdx = main.indexOf('?');
  const beforeQuery = qIdx >= 0 ? main.slice(0, qIdx) : main;
  const query = qIdx >= 0 ? main.slice(qIdx + 1) : '';

  const atIdx = beforeQuery.lastIndexOf('@');
  if (atIdx < 0) throw new Error('missing @');

  const uuid = beforeQuery.slice(0, atIdx);
  const hostPort = beforeQuery.slice(atIdx + 1);

  let host, port;
  if (hostPort.startsWith('[')) {
    const end = hostPort.indexOf(']');
    host = hostPort.slice(1, end);
    port = parseInt(hostPort.slice(end + 2), 10);
  } else {
    const colonIdx = hostPort.lastIndexOf(':');
    host = hostPort.slice(0, colonIdx);
    port = parseInt(hostPort.slice(colonIdx + 1), 10);
  }

  const params = new URLSearchParams(query);
  return {
    uuid,
    host,
    port,
    name,
    type: params.get('type') || 'tcp',
    security: params.get('security') || 'none',
    sni: params.get('sni') || params.get('serverName') || '',
    host_header: params.get('host') || '',
    path: params.get('path') || '/',
    alpn: params.get('alpn') || '',
    fp: params.get('fp') || '',
    allowInsecure: params.get('allowInsecure') === '1' || params.get('allowInsecure') === 'true',
  };
}

function buildVlessUrl(cfg) {
  const params = new URLSearchParams();
  params.set('type', cfg.type || 'ws');
  if (cfg.security) params.set('security', cfg.security);
  if (cfg.sni) params.set('sni', cfg.sni);
  if (cfg.host_header) params.set('host', cfg.host_header);
  if (cfg.path) params.set('path', cfg.path);
  if (cfg.alpn) params.set('alpn', cfg.alpn);
  if (cfg.fp) params.set('fp', cfg.fp);
  if (cfg.allowInsecure) params.set('allowInsecure', '1');

  const name = cfg.name ? `#${encodeURIComponent(cfg.name)}` : '';
  const hostPart = cfg.host.includes(':') ? `[${cfg.host}]` : cfg.host;
  return `vless://${cfg.uuid}@${hostPart}:${cfg.port}?${params.toString()}${name}`;
}

function buildSpoofedConfig(original, opts) {
  const {
    fakeDomain,
    publicHost,
    publicPort,
    path,
    uuid,
    tlsEnabled,
  } = opts;

  return {
    uuid: uuid || original.uuid,
    host: publicHost,
    port: publicPort || 443,
    name: `GhostSNI-${fakeDomain}`,
    type: 'ws',
    security: tlsEnabled ? 'tls' : 'none',
    sni: tlsEnabled ? fakeDomain : '',
    host_header: fakeDomain,
    path: path || '/ws',
    allowInsecure: tlsEnabled,
  };
}

module.exports = { parseVlessUrl, buildVlessUrl, buildSpoofedConfig };
