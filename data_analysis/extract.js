// dynamic_analysis/extract.js
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

const https = require('https');
const http = require('http');

/**
 * Normalize a hostname by trying HTTPS, then HTTP if necessary.
 * Returns full working URL or null if neither works.
 * @param {string} raw - A hostname or URL-like string
 * @returns {Promise<string|null>}
 */
async function normalizeUrl(raw) {
  if (!raw || typeof raw !== 'string') return null;

  const cleaned = raw.trim();

  const options = { method: 'HEAD', timeout: 5000 };

  // Try full URL if it looks valid
  if (/^https?:\/\//i.test(cleaned)) {
    try {
      const urlObj = new URL(cleaned); // sanity check
      const proto = urlObj.protocol === 'https:' ? https : http;
      return await new Promise(resolve => {
        const req = proto.request(cleaned, options, () => resolve(cleaned));
        req.on('error', () => resolve(null));
        req.end();
      });
    } catch {
      return null;
    }
  }

  // Try HTTPS then HTTP if it's just a hostname
  return await new Promise(resolve => {
    https.request(`https://${cleaned}`, options, res => {
      resolve(`https://${cleaned}`);
    }).on('error', () => {
      http.request(`http://${cleaned}`, options, res => {
        resolve(`http://${cleaned}`);
      }).on('error', () => {
        resolve(null);
      }).end();
    }).end();
  });
}


// Random sample of size n
function sampleSize(arr, n) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0 && i > a.length - n - 1; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, Math.min(n, a.length));
}

// Static URL‐based features
function extractStaticFeatures(rawUrl) {
  const { URL } = require('url');
  const parsed = new URL(rawUrl);
  const hostname = parsed.hostname;
  const full = rawUrl.toLowerCase();

  const specials = ['%', '-', '=', '&', ';'];
  const keywords = ['login','verify','secure','account','signin'];

  const url_length = full.length;
  const dot_count = (hostname.match(/\./g) || []).length;
  const has_at = full.includes('@') ? 1 : 0;
  const special_char_count = specials.reduce((s,ch) => s + ((full.split(ch).length-1)), 0);
  const entropy = (() => {
    const counts = {}, L = hostname.length;
    for (const c of hostname) counts[c]=(counts[c]||0)+1;
    return -Object.values(counts).reduce((s,f) => s + (f/L)*Math.log2(f/L), 0);
  })();
  const suspicious_keywords = keywords.reduce((s,kw) => s + (full.includes(kw)?1:0), 0);
  const parts = hostname.split('.');
  const subdomain_length = parts.length>=3 ? parts.slice(0,-2).join('.').length : 0;
  const freeHosts = ["000webhost","freehostia","neocities","wordpress","blogspot","netlify","weebly","github","weeblysite"];
  const domain = parts.slice(-2)[0].toLowerCase();
  const is_free_hosting = freeHosts.includes(domain)?1:0;
  const has_hyphen = hostname.includes('-')?1:0;
  const is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)?1:0;

  return { url_length, dot_count, has_at, special_char_count,
           entropy, suspicious_keywords, subdomain_length,
           is_free_hosting, has_hyphen, is_ip };
}

// Dynamic feature extraction
async function extractDynamicFeatures(rawUrl) {
  const url = await normalizeUrl(rawUrl);
  if (!url) throw new Error(`Invalid URL: "${rawUrl}"`);

  const extensionPath = path.resolve(__dirname, '../SimpleExtension');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`
    ]
  });
  const page = await context.newPage();

  // Initialize counters
  let networkRequestsCount   = 0;
  let externalScriptLoads    = 0;
  let evalUsageCount         = 0;
  let fetchCount             = 0;
  let xhrCount               = 0;
  let wsCount                = 0;
  let scriptInjectionCount   = 0;
  let eventListenerCount     = 0;
  let attributeMutationCount = 0;

  // Network requests
  page.on('request', () => { networkRequestsCount++; });
  // External JS loads
  page.on('response', resp => {
    const ct = resp.headers()['content-type']||'';
    if (ct.includes('javascript') && !resp.url().includes('localhost')) {
      externalScriptLoads++;
    }
  });

  // Instrument dynamic APIs
  await page.addInitScript(() => {
    // eval / Function
    const oldEval = window.eval;
    window.eval = str => {
      window.__evalCount = (window.__evalCount||0) + 1;
      return oldEval(str);
    };
    const oldFunc = window.Function;
    window.Function = (...args) => {
      window.__evalCount = (window.__evalCount||0) + 1;
      return oldFunc(...args);
    };

    // fetch()
    const oldFetch = window.fetch;
    window.fetch = (...args) => {
      window.__fetchCount = (window.__fetchCount||0) + 1;
      return oldFetch(...args);
    };

    // XMLHttpRequest
    const OldXHR = window.XMLHttpRequest;
    window.XMLHttpRequest = function() {
      const xhr = new OldXHR();
      xhr.addEventListener('loadstart', () => {
        window.__xhrCount = (window.__xhrCount||0) + 1;
      });
      return xhr;
    };

    // WebSocket
    const OldWS = window.WebSocket;
    window.WebSocket = function(...args) {
      window.__wsCount = (window.__wsCount||0) + 1;
      return new OldWS(...args);
    };

    // <script> injection
    const origCreate = Document.prototype.createElement;
    Document.prototype.createElement = function(tag, opts) {
      const el = origCreate.call(this, tag, opts);
      if (tag.toLowerCase()==='script') {
        window.__scriptInjectionCount = (window.__scriptInjectionCount||0) + 1;
      }
      return el;
    };

    // addEventListener
    const origAddEvt = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, fn, opts) {
      window.__eventListenerCount = (window.__eventListenerCount||0) + 1;
      return origAddEvt.call(this, type, fn, opts);
    };
  });

  // Page load
  const start = Date.now();
  await page.goto(url, { waitUntil: 'load', timeout: 30000 });
  const pageLoadTime = Date.now() - start;

  // Pull back counters
  evalUsageCount         = await page.evaluate(()=> window.__evalCount         || 0);
  fetchCount             = await page.evaluate(()=> window.__fetchCount        || 0);
  xhrCount               = await page.evaluate(()=> window.__xhrCount          || 0);
  wsCount                = await page.evaluate(()=> window.__wsCount           || 0);
  scriptInjectionCount   = await page.evaluate(()=> window.__scriptInjectionCount || 0);
  eventListenerCount     = await page.evaluate(()=> window.__eventListenerCount   || 0);

  // DOM mutations
  const domMutationCount = await page.evaluate(() => new Promise(resolve => {
    let c=0;
    const o=new MutationObserver(ms=> c+=ms.length);
    o.observe(document, { childList:true, subtree:true });
    setTimeout(() => { o.disconnect(); resolve(c); }, 3000);
  }));

  // Attribute mutations
  attributeMutationCount = await page.evaluate(() => new Promise(resolve => {
    let c=0;
    const o=new MutationObserver(ms=>
      ms.forEach(m=> m.type==='attributes' && c++)
    );
    o.observe(document, { attributes:true, subtree:true });
    setTimeout(() => { o.disconnect(); resolve(c); }, 3000);
  }));

  // Performance metrics
  const perf = await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0];
    return {
      cpuTime: Math.round(performance.now() - nav.domContentLoadedEventEnd),
      memoryUsed: performance.memory?.usedJSHeapSize || 0
    };
  });

  await browser.close();

  return {
    url: rawUrl,
    networkRequestsCount,
    externalScriptLoads,
    evalUsageCount,
    fetchCount,
    xhrCount,
    wsCount,
    scriptInjectionCount,
    eventListenerCount,
    domMutationCount,
    attributeMutationCount,
    pageLoadTime,
    cpuTime: perf.cpuTime,
    memoryUsed: perf.memoryUsed
  };
}

// Main: build dataset
(async () => {
  console.log("Running sript");
  const benignPath   = path.resolve(__dirname, '../../datasets/benign.csv');
  const phishingPath = path.resolve(__dirname, '../../datasets/phishing.csv');

  const benignUrls   = await readUrlsFromCsv(benignPath);
  const phishingUrls = await readUrlsFromCsv(phishingPath);

  const sampleBenign   = sampleSize(benignUrls, 5000);
  const samplePhishing = sampleSize(phishingUrls, 5000);

  const entries = sampleBenign.map(u=>({url:u,label:0}))
    .concat(samplePhishing.map(u=>({url:u,label:1})));

  const outDir = path.resolve(__dirname, '../../datasets');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'features.csv');

  // Write header
  const first = entries[0];
  const statKeys = Object.keys(extractStaticFeatures(await normalizeUrl(first.url)));
  const dynKeys  = Object.keys(await extractDynamicFeatures(first.url));
  const header   = statKeys.concat(dynKeys, ['label']).join(',');
  fs.writeFileSync(outFile, header + '\n');

  // Write each row
  const concurrency = 5;  // Try 5-10 depending on your system
  for (let i = 0; i < entries.length; i += concurrency) {
    const batch = entries.slice(i, i + concurrency);
    const results = await Promise.allSettled(batch.map(async ({ url, label }) => {
      try {
        const nurl = await normalizeUrl(url);
        if (!nurl) throw new Error('Invalid normalized URL');

        const stat = extractStaticFeatures(nurl);
        const dyn = await extractDynamicFeatures(nurl);
        const row = Object.values(stat)
          .concat(Object.values(dyn), [label])
          .join(',');
        return row;
      } catch (e) {
        console.error(`❌ ${url} — ${e.message}`);
        return null;
      }
    }));

    if ((i + 1) % 100 === 0) {
      console.log(`📦 Processed ${i + 1} samples...`);
    }

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        fs.appendFileSync(outFile, result.value + '\n');
      }
    }
  }

})();
