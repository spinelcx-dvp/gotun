// vless.js
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function uuidToHex(uuid) {
  return uuid.replace(/-/g, '').toLowerCase();
}

function hexToUuid(hex) {
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

function isValidUUID(str) {
  return UUID_RE.test(str);
}

function parseVlessHeader(buf) {
  if (buf.length < 18) return null;
  const version = buf[0];
  const uuidHex = buf.slice(1, 17).toString('hex');
  const addonLen = buf[17];

  let pos = 18 + addonLen;
  if (buf.length < pos + 4) return null;

  const command = buf[pos];
  pos += 1;
  const port = buf.readUInt16BE(pos);
  pos += 2;
  const addrType = buf[pos];
  pos += 1;

  let address = '';
  if (addrType === 1) {
    if (buf.length < pos + 4) return null;
    address = `${buf[pos]}.${buf[pos+1]}.${buf[pos+2]}.${buf[pos+3]}`;
    pos += 4;
  } else if (addrType === 2) {
    if (buf.length < pos + 1) return null;
    const domainLen = buf[pos];
    pos += 1;
    if (buf.length < pos + domainLen) return null;
    address = buf.slice(pos, pos + domainLen).toString('ascii');
    pos += domainLen;
  } else if (addrType === 3) {
    if (buf.length < pos + 16) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(pos + i * 2).toString(16));
    address = parts.join(':');
    pos += 16;
  } else {
    return null;
  }

  return {
    version,
    uuid: hexToUuid(uuidHex),
    uuidHex,
    command,
    port,
    addrType,
    address,
    payload: buf.slice(pos),
    headerLength: pos,
  };
}

module.exports = { parseVlessHeader, isValidUUID, uuidToHex, hexToUuid };
