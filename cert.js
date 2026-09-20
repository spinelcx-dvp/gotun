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
  const tmp = path.join('/tmp', `cert-${crypto.randomBytes(4).toString('hex')}`);
  try {
    execSync(
      `openssl req -x509 -newkey rsa:2048 -nodes ` +
      `-keyout ${tmp}.key -out ${tmp}.crt ` +
      `-days 365 -subj "/CN=${domain}" ` +
      `-addext "subjectAltName=DNS:${domain}"`,
      { stdio: 'ignore' }
    );
    const key = fs.readFileSync(`${tmp}.key`, 'utf8');
    const cert = fs.readFileSync(`${tmp}.crt`, 'utf8');
    fs.unlinkSync(`${tmp}.key`);
    fs.unlinkSync(`${tmp}.crt`);
    return { key, cert };
  } catch (e) {
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
