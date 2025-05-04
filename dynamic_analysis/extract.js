// dynamic_analysis/extract.js
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

function normalizeUrl(url) {
    if (!url) return null;
    url = url.trim();
    if (!/^https?:\/\//i.test(url)) {
      return 'http://' + url;
    }
    return url;
  }  

//  Helper: read all URLs from a CSV (assumes a column named "url") 
function readUrlsFromCsv(csvPath) {
  return new Promise(resolve => {
    const urls = [];
    fs.createReadStream(csvPath)
      .pipe(csv())
      .on('data', row => urls.push(row.url))
      .on('end', () => resolve(urls));
  });
}

//  Helper: random sample of size n 
function sampleSize(arr, n) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0 && i > a.length - n - 1; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a.slice(0, Math.min(n, a.length));
}

//  Your existing feature-extraction routine 
async function extractFeatures(url) {
  const extensionPath = path.resolve(__dirname, '../SimpleExtension');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`
    ]
  });
  const page = await context.newPage();

  let networkRequestsCount = 0;
  let externalScriptLoads  = 0;
  let evalUsageCount  = 0;

  // network requests
  page.on('request', () => { networkRequestsCount++; });

  // external scripts
  page.on('response', resp => {
    const ct = resp.headers()['content-type'] || '';
    if (ct.includes('javascript') && !resp.url().includes('localhost')) {
      externalScriptLoads++;
    }
  });

  // instrument eval()/Function()
  await page.addInitScript(() => {
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
  });

  // navigate & measure load time
  const start = Date.now();
  await page.goto(url, { waitUntil: 'load', timeout: 30000 });
  const pageLoadTime = Date.now() - start;

  // read eval count
  evalUsageCount = await page.evaluate(() => window.__evalCount || 0);

  // count DOM mutations over 3s
  const domMutationCount = await page.evaluate(() => {
    return new Promise(resolve => {
      let count = 0;
      const obs = new MutationObserver(muts => { count += muts.length; });
      obs.observe(document, { childList: true, subtree: true });
      setTimeout(() => { obs.disconnect(); resolve(count); }, 3000);
    });
  });

  // performance metrics
  const perf = await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0];
    return {
      cpuTime:   Math.round(performance.now() - nav.domContentLoadedEventEnd),
      memoryUsed: performance.memory?.usedJSHeapSize || 0
    };
  });

  await browser.close();

  return {
    url,
    networkRequestsCount,
    externalScriptLoads,
    evalUsageCount,
    domMutationCount,
    pageLoadTime,
    cpuTime:   perf.cpuTime,
    memoryUsed: perf.memoryUsed
  };
}

//  Main: read, sample, extract, write 
(async () => {
  // 1. paths to your two CSVs
  const benignPath   = path.resolve(__dirname, '../../datasets/benign.csv');
  const phishingPath = path.resolve(__dirname, '../../datasets/phishing.csv');

  // 2. load & sample
  const benignUrls   = await readUrlsFromCsv(benignPath);
  const phishingUrls = await readUrlsFromCsv(phishingPath);
  const sampleBenign   = sampleSize(benignUrls,   5000);
  const samplePhishing = sampleSize(phishingUrls, 5000);
  const urls = sampleBenign.concat(samplePhishing);

  console.log(`${sampleBenign.length} benign + ${samplePhishing.length} phishing = ${urls.length} URLs`);

  // 3. prepare output CSV
  const outDir = path.resolve(__dirname, '../SimpleExtension/datasets');
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, 'dyn_features.csv');

  // write header row
  console.log(urls[0]);
  const firstUrl = normalizeUrl(urls[0]);
  const header = Object.keys(await extractFeatures(firstUrl)).join(',');

  fs.writeFileSync(outFile, header + '\n');

  // 4. extract features on each URL
  for (let raw of urls) {
    const url = normalizeUrl(raw);
    console.log(url);
    // Skip if invalid
    if (!url || typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
      console.warn(`⛔ Skipping invalid URL: ${raw}`);
      continue;
    }
  
    try {
      const feat = await extractFeatures(url);
      fs.appendFileSync(outFile, Object.values(feat).join(',') + '\n');
      console.log(`✅ Extracted: ${url}`);
    } catch (e) {
      console.error(`❌ Failed: ${url} — ${e.message}`);
    }
  }  
})();
