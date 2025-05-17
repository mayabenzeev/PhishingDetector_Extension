const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');
const https = require('https');
const http = require('http');

console.log('🚀 Optimized script started');

const MAX_BENIGN = 10000;
const CONCURRENCY = 10;
const DYNAMIC_OBSERVATION_MS = 1500;

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

async function normalizeUrl(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const cleaned = raw.trim();
  const options = { method: 'HEAD', timeout: 3000 };

  try {
    const urlObj = new URL(cleaned.startsWith('http') ? cleaned : `https://${cleaned}`);
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

function sampleSize(arr, n) {
  const shuffled = arr.slice();
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, Math.min(n, shuffled.length));
}

function extractStaticFeatures(rawUrl) {
  const { URL } = require('url');
  const parsed = new URL(rawUrl);
  const hostname = parsed.hostname;
  const full = rawUrl.toLowerCase();

  const specials = ['%', '-', '=', '&', ';'];
  const keywords = ['login', 'verify', 'secure', 'account', 'signin'];
  const url_length = full.length;
  const dot_count = (hostname.match(/\./g) || []).length;
  const has_at = full.includes('@') ? 1 : 0;
  const special_char_count = specials.reduce((s, ch) => s + (full.split(ch).length - 1), 0);
  const entropy = (() => {
    const counts = {}, L = hostname.length;
    for (const c of hostname) counts[c] = (counts[c] || 0) + 1;
    return -Object.values(counts).reduce((s, f) => s + (f / L) * Math.log2(f / L), 0);
  })();
  const suspicious_keywords = keywords.reduce((s, kw) => s + (full.includes(kw) ? 1 : 0), 0);
  const parts = hostname.split('.');
  const subdomain_length = parts.length >= 3 ? parts.slice(0, -2).join('.').length : 0;
  const freeHosts = ["000webhost", "freehostia", "neocities", "wordpress", "blogspot", "netlify", "weebly", "github", "weeblysite"];
  const domain = parts.slice(-2)[0].toLowerCase();
  const is_free_hosting = freeHosts.includes(domain) ? 1 : 0;
  const has_hyphen = hostname.includes('-') ? 1 : 0;
  const is_ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0;

  return {
    url_length,
    dot_count,
    has_at,
    special_char_count,
    entropy,
    suspicious_keywords,
    subdomain_length,
    is_free_hosting,
    has_hyphen,
    is_ip
  };
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
  const fetchCount = await safeEvaluate(page, () => window.__fetchCount || 0);
  const xhrCount = await safeEvaluate(page, () => window.__xhrCount || 0);
  const wsCount = await safeEvaluate(page, () => window.__wsCount || 0);
  const scriptInjectionCount = await safeEvaluate(page, () => window.__scriptInjectionCount || 0);
  const eventListenerCount = await safeEvaluate(page, () => window.__eventListenerCount || 0);

const domMutationCount = await safeEvaluate(page, () => new Promise(resolve => {
  let c = 0;
  const o = new MutationObserver(ms => c += ms.length);
  o.observe(document, { childList: true, subtree: true });
  setTimeout(() => { o.disconnect(); resolve(c); }, DYNAMIC_OBSERVATION_MS);
}));

const attributeMutationCount = await safeEvaluate(page, () => new Promise(resolve => {
  let c = 0;
  const o = new MutationObserver(ms => {
    ms.forEach(m => m.type === 'attributes' && c++);
  });
  o.observe(document, { attributes: true, subtree: true });
  setTimeout(() => { o.disconnect(); resolve(c); }, DYNAMIC_OBSERVATION_MS);
}));


  const perf = await safeEvaluate(page, () => {
    const nav = performance.getEntriesByType('navigation')[0];
    return {
      cpuTime: performance.now() - nav.domContentLoadedEventEnd,
      memoryUsed: performance.memory?.usedJSHeapSize || 0
    };
  });

  return {
    evalUsageCount,
    fetchCount,
    xhrCount,
    wsCount,
    scriptInjectionCount,
    eventListenerCount,
    domMutationCount,
    attributeMutationCount,
    pageLoadTime: perf.cpuTime,
    memoryUsed: perf.memoryUsed
  };
}

(async () => {
  const benignPath = path.resolve(__dirname, '../datasets/benign.csv');
  const output = path.resolve(__dirname, '../datasets/features.csv');
  const extensionPath = path.resolve(__dirname, '../SimpleExtension');

  if (!fs.existsSync(output)) {
    fs.writeFileSync(output, 'url,url_length,dot_count,has_at,special_char_count,entropy,suspicious_keywords,subdomain_length,is_free_hosting,has_hyphen,is_ip,evalUsageCount,fetchCount,xhrCount,wsCount,scriptInjectionCount,eventListenerCount,domMutationCount,attributeMutationCount,pageLoadTime,memoryUsed,label\n');
  }

  const { seen: processed, benign: benignCountStart } = await loadProcessedData(output);
  let benignCount = benignCountStart;

  const benignUrls = (await readUrlsFromCsv(benignPath)).map(u => ({ url: u, label: 0 }));
  const benignQueue = sampleSize(benignUrls, benignUrls.length);
  const startTime = Date.now();

  console.log('⚡ Processing benign URLs only...');

  const browser = await chromium.launch({ headless: true });
  const processBatch = async (batch) => {
    await Promise.allSettled(batch.map(async ({ url, label }) => {
      if (processed.has(url) || benignCount >= MAX_BENIGN) return;

      const normalized = await normalizeUrl(url);
      if (!normalized) return;

      const context = await browser.newContext({
        args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`]
      });

      try {
        const page = await context.newPage();
        await page.goto(normalized, { waitUntil: 'load', timeout: 10000 });

        const staticFeats = extractStaticFeatures(normalized);
        const dynamicFeats = await extractDynamicFeatures(page);
        const row = [normalized, ...Object.values(staticFeats), ...Object.values(dynamicFeats), label].join(',');
        fs.appendFileSync(output, row + '\n');

        benignCount++;
        if (benignCount % 10 === 0) {
          const elapsed = (Date.now() - startTime) / 1000;
          const eta = ((MAX_BENIGN - benignCount) * (elapsed / benignCount)).toFixed(1);
          console.log(`✅ ${benignCount}/${MAX_BENIGN} — ${normalized} | ETA: ${eta}s`);
        }
      } catch (err) {
        console.warn(`⚠️ Skipped ${url}: ${err.message}`);
      } finally {
        await context.close();
      }
    }));
  };

  while (benignCount < MAX_BENIGN && benignQueue.length > 0) {
    const batch = benignQueue.splice(0, CONCURRENCY);
    await processBatch(batch);
  }

  await browser.close();
  console.log(`🏁 Done: Processed ${benignCount} benign URLs.`);
})();
