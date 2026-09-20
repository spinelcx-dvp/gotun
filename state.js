// state.js
// وضعیت runtime که از UI قابل تغییره

const state = {
  // دامنه‌های جعلی مجاز (از UI قابل ویرایش)
  fakeDomains: [
    'chatgpt.com',
    'www.microsoft.com',
    'www.bing.com',
    'www.apple.com',
    'www.cloudflare.com',
    'www.google.com',
  ],

  // پاسخ واقعی برای SNI نامعتبر (anti active probing)
  fakeResponse: true,

  // fragment کردن ClientHello
  fragmentHello: false,

  // مسیر پیش‌فرض WS
  defaultWsPath: '/ws',

  // حالت TLS (اگه false باشه، بدون TLS spoof می‌کنه)
  tlsEnabled: true,

  // لیست UUID های مجاز (خالی = همه مجاز)
  allowedUuids: [],
};

function getState() {
  return state;
}

function updateState(patch) {
  if (patch.fakeDomains && Array.isArray(patch.fakeDomains)) {
    state.fakeDomains = patch.fakeDomains
      .map(d => String(d).trim().toLowerCase())
      .filter(Boolean)
      .filter((v, i, a) => a.indexOf(v) === i);
  }
  if (typeof patch.fakeResponse === 'boolean') state.fakeResponse = patch.fakeResponse;
  if (typeof patch.fragmentHello === 'boolean') state.fragmentHello = patch.fragmentHello;
  if (typeof patch.tlsEnabled === 'boolean') state.tlsEnabled = patch.tlsEnabled;
  if (typeof patch.defaultWsPath === 'string') {
    state.defaultWsPath = patch.defaultWsPath.startsWith('/')
      ? patch.defaultWsPath
      : '/' + patch.defaultWsPath;
  }
  if (Array.isArray(patch.allowedUuids)) {
    state.allowedUuids = patch.allowedUuids.map(s => String(s).trim()).filter(Boolean);
  }
  return state;
}

module.exports = { getState, updateState };
