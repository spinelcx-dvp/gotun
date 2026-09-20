// sni.js
function extractSNI(buf) {
  try {
    if (buf.length < 5 || buf[0] !== 0x16) return null;
    if (buf.length < 6 || buf[5] !== 0x01) return null;

    let pos = 9;
    pos += 2;
    pos += 32;

    if (buf.length < pos + 1) return null;
    const sidLen = buf[pos];
    pos += 1 + sidLen;

    if (buf.length < pos + 2) return null;
    const csLen = buf.readUInt16BE(pos);
    pos += 2 + csLen;

    if (buf.length < pos + 1) return null;
    const cmLen = buf[pos];
    pos += 1 + cmLen;

    if (buf.length < pos + 2) return null;
    const extLen = buf.readUInt16BE(pos);
    pos += 2;
    const extEnd = pos + extLen;
    if (buf.length < extEnd) return null;

    while (pos + 4 <= extEnd) {
      const extType = buf.readUInt16BE(pos);
      const extSize = buf.readUInt16BE(pos + 2);
      pos += 4;

      if (extType === 0x00) {
        if (pos + 2 > extEnd) return null;
        const listLen = buf.readUInt16BE(pos);
        pos += 2;
        const listEnd = pos + listLen;

        while (pos + 3 <= listEnd) {
          const nameType = buf[pos];
          const nameLen = buf.readUInt16BE(pos + 1);
          pos += 3;
          if (nameType === 0x00) {
            if (pos + nameLen > listEnd) return null;
            return buf.slice(pos, pos + nameLen).toString('ascii');
          }
          pos += nameLen;
        }
      }
      pos += extSize;
    }
    return null;
  } catch {
    return null;
  }
}

function isCompleteClientHello(buf) {
  if (buf.length < 5) return false;
  if (buf[0] !== 0x16) return false;
  const recordLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recordLen) return false;
  if (buf.length < 9) return false;
  const hsLen = (buf[6] << 16) | (buf[7] << 8) | buf[8];
  return buf.length >= 9 + hsLen;
}

module.exports = { extractSNI, isCompleteClientHello };
