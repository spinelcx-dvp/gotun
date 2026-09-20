// cert.js
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const CACHE_DIR = path.join(__dirname, 'certs');
const cache = new Map();

function ensureDir() {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function certPath(domain) {
  return path.join(CACHE_DIR, `${domain}.json`);
}

function fetchCertFromDomain(domain) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false,
    }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.end();
      if (!cert || !cert.raw) return reject(new Error(`no cert for ${domain}`));
      const chain = [];
      let c = cert;
      const seen = new Set();
      while (c && c.raw && !seen.has(c.fingerprint)) {
        seen.add(c.fingerprint);
        chain.push(c.raw.toString('base64'));
        c = c.issuerCertificate;
      }
      resolve({ domain, chain });
    });
    socket.on('error', reject);
    socket.setTimeout(8000, () => {
      socket.destroy();
      reject(new Error(`timeout fetching cert for ${domain}`));
    });
  });
}

function generateSelfSigned(domain) {
  const base = path.join('/tmp', `cert-${crypto.randomBytes(6).toString('hex')}`);
  const keyPath = `${base}.key`;
  const crtPath = `${base}.crt`;
  const cnfPath = `${base}.cnf`;

  const cnf = `[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${domain}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${domain}
`;

  try {
    fs.writeFileSync(cnfPath, cnf);

    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes ` +
      `-keyout ${keyPath} -out ${crtPath} ` +
      `-days 365 -config ${cnfPath}`,
      { stdio: 'pipe' }
    );

    const key = fs.readFileSync(keyPath, 'utf8');
    const certPem = fs.readFileSync(crtPath, 'utf8');

    const fpOut = execSync(
      `openssl x509 -in ${crtPath} -noout -fingerprint -sha256`,
      { encoding: 'utf8' }
    ).trim();

    let fingerprint = '';
    const eqIdx = fpOut.indexOf('=');
    if (eqIdx >= 0) {
      fingerprint = fpOut.slice(eqIdx + 1).replace(/:/g, '').toLowerCase();
    }

    if (!fingerprint || !/^[0-9a-f]+$/.test(fingerprint)) {
      throw new Error('fingerprint extraction failed: ' + fpOut);
    }

    fs.unlinkSync(keyPath);
    fs.unlinkSync(crtPath);
    fs.unlinkSync(cnfPath);

    return { key, cert: certPem, fingerprint };
  } catch (e) {
    try { fs.unlinkSync(keyPath); } catch {}
    try { fs.unlinkSync(crtPath); } catch {}
    try { fs.unlinkSync(cnfPath); } catch {}
    throw new Error(`self-signed failed: ${e.message}`);
  }
}

async function getCert(domain) {
  if (cache.has(domain)) return cache.get(domain);
  ensureDir();

  let realChain = null;
  try {
    realChain = await fetchCertFromDomain(domain);
  } catch {}

  const self = generateSelfSigned(domain);
  const result = {
    key: self.key,
    cert: self.cert,
    fingerprint: self.fingerprint,
    realChain: realChain ? realChain.chain : null,
    domain,
    fetchedAt: Date.now(),
  };

  try {
    fs.writeFileSync(certPath(domain), JSON.stringify(result, null, 2));
  } catch {}
  cache.set(domain, result);
  return result;
}

module.exports = { getCert };
