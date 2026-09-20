// spoof.js
const { getState } = require('./state');
const { getCert } = require('./cert');

function isFakeDomain(sni) {
  const { fakeDomains } = getState();
  return fakeDomains.includes(String(sni).toLowerCase());
}

async function getSpoofContext(sni) {
  const cert = await getCert(sni);
  return {
    sni,
    cert: cert.cert,
    key: cert.key,
    realChain: cert.realChain,
  };
}

module.exports = { isFakeDomain, getSpoofContext };
