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

  if (/^https?:\/\//i.test(cleaned)) {
    try {
      const urlObj = new URL(cleaned);
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

function readUrlsFromCsv(csvPath) {
  return new Promise((resolve, reject) => {
    const urls = [];
    fs.createReadStream(csvPath)
      .pipe(csv())
      .on('data', row => {
        if (row.url) urls.push(row.url);
      })
      .on('end', () => resolve(urls))
      .on('error', err => reject(err));
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

function sampleSize(arr, n) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, Math.min(n, a.length));
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
      await page.waitForTimeout(500);
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
    setTimeout(() => { o.disconnect(); resolve(c); }, 3000);
  }));

  const attributeMutationCount = await safeEvaluate(page, () => new Promise(resolve => {
    let c = 0;
    const o = new MutationObserver(ms => {
      ms.forEach(m => m.type === 'attributes' && c++);
    });
    o.observe(document, { attributes: true, subtree: true });
    setTimeout(() => { o.disconnect(); resolve(c); }, 3000);
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
  const phishingPath = path.resolve(__dirname, '../datasets/phishing.csv');
  const extensionPath = path.resolve(__dirname, '../SimpleExtension');
  const output = path.resolve(__dirname, '../datasets/features.csv');


  if (!fs.existsSync(output)) {
    fs.writeFileSync(output, 'url,url_length,dot_count,has_at,special_char_count,entropy,suspicious_keywords,subdomain_length,is_free_hosting,has_hyphen,is_ip,evalUsageCount,fetchCount,xhrCount,wsCount,scriptInjectionCount,eventListenerCount,domMutationCount,attributeMutationCount,pageLoadTime,memoryUsed,label\n');
  }
  const { seen: processedURLs, benign: benignCountStart, phishing: phishingCountStart } = await loadProcessedData(output);
  let benignCount = benignCountStart;
  let phishingCount = phishingCountStart;


  const benign = (await readUrlsFromCsv(benignPath)).map(u => ({ url: u, label: 0 }));
  const phishing = (await readUrlsFromCsv(phishingPath)).map(u => ({ url: u, label: 1 }));
  let benignQueue = sampleSize(benign, benign.length);
  let phishingQueue = sampleSize(phishing, phishing.length);

  const maxEach = 5000;
  const concurrency = 5;
  const startTime = Date.now();

  while ((benignCount < maxEach || phishingCount < maxEach) && (benignQueue.length > 0 || phishingQueue.length > 0)) {
    const batch = [];
    while (batch.length < concurrency && (benignQueue.length > 0 || phishingQueue.length > 0)) {
      if ((benignCount < maxEach && Math.random() < 0.5 && benignQueue.length > 0) || phishingQueue.length === 0) {
        batch.push(benignQueue.pop());
      } else if (phishingQueue.length > 0) {
        batch.push(phishingQueue.pop());
      }
    }

    const promises = batch.map(async ({ url, label }) => {
      if (processedURLs.has(url)) return;
      if ((label === 0 && benignCount >= maxEach) || (label === 1 && phishingCount >= maxEach)) return;

      const normalized = await normalizeUrl(url);
      if (!normalized) return;

      let browser;
      try {
        browser = await chromium.launch({ headless: true, timeout: 15000 });
        const context = await browser.newContext({
          args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`
          ]
        });
        const page = await context.newPage();

        await page.goto(normalized, { waitUntil: 'load', timeout: 10000 });

        const staticFeats = extractStaticFeatures(normalized);
        const dynamicFeats = await extractDynamicFeatures(page);

        const row = [normalized, ...Object.values(staticFeats), ...Object.values(dynamicFeats), label].join(',');
        fs.appendFileSync(output, row + '\n');

        if (label === 0) benignCount++;
        else phishingCount++;

        const elapsed = (Date.now() - startTime) / 1000;
        const total = benignCount + phishingCount;
        const remaining = 10000 - total;
        const eta = total > 0 ? Math.round(elapsed / total * remaining) : '?';

        if (total % 10 === 0) {
          console.log(`✅ ${label === 0 ? 'Benign' : 'Phishing'} (${benignCount}/${phishingCount}) — ${normalized} | ETA: ~${eta}s`);
        }
      } catch (err) {
        console.warn(`⚠️  Skipped ${url}: ${err.message}`);
      } finally {
        if (browser) await browser.close();
      }
    });

    await Promise.allSettled(promises);
  }

  console.log(`🏁 Done: ${benignCount} benign, ${phishingCount} phishing`);
})();
