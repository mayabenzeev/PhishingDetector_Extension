// dynamic_analysis/extract.js

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const https = require('https');
const http = require('http');

async function normalizeUrl(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const cleaned = raw.trim();
  const options = { method: 'HEAD', timeout: 5000 };
  try {
    const urlObj = new URL(/^https?:\/\//i.test(cleaned) ? cleaned : `https://${cleaned}`);
    const proto = urlObj.protocol === 'https:' ? https : http;
    return await new Promise(resolve => {
      const req = proto.request(urlObj.href, options, () => resolve(urlObj.href));
      req.on('error', () => resolve(null));
      req.end();
    });
  } catch {
    return null;
  }
}

function readUrlsFromCsv(csvPath) {
  return new Promise((resolve, reject) => {
    const urls = [];
    fs.createReadStream(csvPath)
      .pipe(csv())
      .on('data', row => row.url && urls.push(row.url))
      .on('end', () => resolve(urls))
      .on('error', reject);
  });
}

function loadProcessedData(csvPath) {
  return new Promise((resolve, reject) => {
    const seen = new Set();
    let benign = 0, phishing = 0;
    if (!fs.existsSync(csvPath)) return resolve({ seen, benign, phishing });
    fs.createReadStream(csvPath)
      .pipe(csv())
      .on('data', row => {
        if (row.url) {
          seen.add(row.url);
          if (row.label === '0') benign++;
          else if (row.label === '1') phishing++;
        }
      })
      .on('end', () => resolve({ seen, benign, phishing }))
      .on('error', reject);
  });
}

function sample(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function extractStaticFeatures(rawUrl) {
  const { URL } = require('url');
  const parsed = new URL(rawUrl);
  const hostname = parsed.hostname.toLowerCase();
  const full = rawUrl.toLowerCase();
  const specials = ['%', '-', '=', '&', ';'];
  const keywords = ['login','verify','secure','account','signin'];

  const url_length = full.length;
  const dot_count = (hostname.match(/\./g) || []).length;
  const has_at = full.includes('@') ? 1 : 0;
  const special_char_count = specials.reduce((s,ch)=>s + (full.split(ch).length - 1),0);
  const entropy = (() => {
    const counts = {}, L = hostname.length;
    for (const c of hostname) counts[c] = (counts[c]||0) + 1;
    return -Object.values(counts).reduce((sum,f)=> sum + (f/L)*Math.log2(f/L), 0);
  })();
  const suspicious_keywords = keywords.reduce((sum,kw)=> sum + (full.includes(kw)?1:0), 0);
  const parts = hostname.split('.');
  const subdomain_length = parts.length >= 3 ? parts.slice(0,-2).join('.').length : 0;
  const freeHosts = ["000webhost","freehostia","neocities","wordpress","blogspot","netlify","weebly","github","weeblysite"];
  const domain = parts.slice(-2)[0];
  const is_free_hosting = freeHosts.includes(domain) ? 1 : 0;
  const has_hyphen = hostname.includes('-') ? 1 : 0;
  const is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0;

  return { url_length,dot_count,has_at,special_char_count,entropy,
           suspicious_keywords,subdomain_length,is_free_hosting,has_hyphen,is_ip };
}

async function safeEvaluate(page, fn) {
  try {
    return await page.evaluate(fn);
  } catch (e) {
    if (e.message.includes('Execution context was destroyed')) {
      await page.waitForTimeout(300);
      return await page.evaluate(fn);
    }
    throw e;
  }
}

async function extractDynamicFeatures(page) {
  const evalUsageCount = await safeEvaluate(page, () => window.__evalCount || 0);
  const fetchCount     = await safeEvaluate(page, () => window.__fetchCount || 0);
  const xhrCount       = await safeEvaluate(page, () => window.__xhrCount || 0);
  const wsCount        = await safeEvaluate(page, () => window.__wsCount || 0);
  const scriptInjectionCount = await safeEvaluate(page, () => window.__scriptInjectionCount || 0);
  const eventListenerCount   = await safeEvaluate(page, () => window.__eventListenerCount || 0);

  const domMutationCount = await safeEvaluate(page, () =>
    new Promise(resolve => {
      let c = 0;
      const o = new MutationObserver(ms => c += ms.length);
      o.observe(document, { childList: true, subtree: true });
      setTimeout(() => { o.disconnect(); resolve(c); }, 5000);
    })
  );

  const attributeMutationCount = await safeEvaluate(page, () =>
    new Promise(resolve => {
      let c = 0;
      const o = new MutationObserver(ms => {
        ms.forEach(m => m.type === 'attributes' && c++);
      });
      o.observe(document, { attributes: true, subtree: true });
      setTimeout(() => { o.disconnect(); resolve(c); }, 5000);
    })
  );

  const perf = await safeEvaluate(page, () => {
    const nav = performance.getEntriesByType('navigation')[0];
    return {
      cpuTime: performance.now() - nav.domContentLoadedEventEnd,
      memoryUsed: performance.memory?.usedJSHeapSize || 0
    };
  });

  return { evalUsageCount,fetchCount,xhrCount,wsCount,
           scriptInjectionCount,eventListenerCount,
           domMutationCount,attributeMutationCount,
           pageLoadTime: perf.cpuTime, memoryUsed: perf.memoryUsed };
}

(async () => {
  const MAX_BENIGN   = 10000;
  const MAX_PHISHING = 1000;
  const CONCURRENCY  = 5;

  const benignPath   = path.resolve(__dirname, '../datasets/benign.csv');
  const phishingPath = path.resolve(__dirname, '../datasets/phishing.csv');
  const output       = path.resolve(__dirname, '../datasets/features.csv');

  if (!fs.existsSync(output)) {
    fs.writeFileSync(output,
      'url,url_length,dot_count,has_at,special_char_count,entropy,'+
      'suspicious_keywords,subdomain_length,is_free_hosting,has_hyphen,is_ip,'+
      'evalUsageCount,fetchCount,xhrCount,wsCount,scriptInjectionCount,'+
      'eventListenerCount,domMutationCount,attributeMutationCount,'+
      'pageLoadTime,memoryUsed,label\n'
    );
  }

  const { seen, benign: b0, phishing: p0 } = await loadProcessedData(output);
  let benignCount   = b0;
  let phishingCount = p0;

  const benignUrls   = (await readUrlsFromCsv(benignPath)).map(u => ({ url: u, label: 0 }));
  const phishingUrls = (await readUrlsFromCsv(phishingPath)).map(u => ({ url: u, label: 1 }));
  let queue = sample([...benignUrls, ...phishingUrls]);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();

  // inject instrumentation
  await context.addInitScript({ content: `
    (function() {
      window.__evalCount = 0;
      const _eval = window.eval;
      window.eval = function() { window.__evalCount++; return _eval.apply(this, arguments); };
      window.__fetchCount = 0;
      const _fetch = window.fetch;
      window.fetch = function() { window.__fetchCount++; return _fetch.apply(this, arguments); };
      window.__xhrCount = 0;
      const _open = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function() {
        this.addEventListener('loadend', () => { window.__xhrCount++; });
        return _open.apply(this, arguments);
      };
      window.__wsCount = 0;
      const _WS = WebSocket;
      window.WebSocket = function(...args) { window.__wsCount++; return new _WS(...args); };
      window.__scriptInjectionCount = 0;
      const _create = Document.prototype.createElement;
      Document.prototype.createElement = function(tag) {
        const el = _create.call(this, tag);
        if (tag.toLowerCase()==='script') window.__scriptInjectionCount++;
        return el;
      };
      window.__eventListenerCount = 0;
      const _addEvt = EventTarget.prototype.addEventListener;
      EventTarget.prototype.addEventListener = function(t, fn, o) {
        window.__eventListenerCount++;
        return _addEvt.call(this, t, fn, o);
      };
    })();
  `});

  const start = Date.now();
  while ((benignCount < MAX_BENIGN || phishingCount < MAX_PHISHING) && queue.length) {
    const batch = queue.splice(0, CONCURRENCY);
    await Promise.all(batch.map(async ({ url, label }) => {
      if (seen.has(url)) return;
      if ((label === 0 && benignCount >= MAX_BENIGN) || (label === 1 && phishingCount >= MAX_PHISHING)) return;

      const norm = await normalizeUrl(url);
      if (!norm) return;

      const page = await context.newPage();
      try {
        await page.goto(norm, { waitUntil: 'load', timeout: 20000 });
        const s = extractStaticFeatures(norm);
        const d = await extractDynamicFeatures(page);
        // replace commas in URL to avoid quotes
        const safeUrl = norm.replace(/,/g, '%2C');
        const row = [safeUrl, ...Object.values(s), ...Object.values(d), label].join(',');
        fs.appendFileSync(output, row + '\n');

        if (label === 0) benignCount++;
        else phishingCount++;

        const total = benignCount + phishingCount;
        if (total % 10 === 0) {
          const elapsed = (Date.now() - start) / 1000;
          const remaining = (MAX_BENIGN - benignCount) + (MAX_PHISHING - phishingCount);
          const eta = total > 0 ? Math.round(remaining * (elapsed / total)) : '?';
          console.log(`✅ Benign=${benignCount}/${MAX_BENIGN}, Phishing=${phishingCount}/${MAX_PHISHING} | ETA ~${eta}s`);
        }
      } catch (e) {
        console.warn(`⚠️ Skip ${norm}: ${e.message}`);
      } finally {
        await page.close();
      }
    }));
  }

  await browser.close();
  console.log(`🏁 Completed: benign=${benignCount}, phishing=${phishingCount}`);
})();
