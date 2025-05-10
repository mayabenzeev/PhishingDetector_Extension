// content-script.js (Random Forest only)
let rfForest = null;
const rfThreshold = 0.58; // Adjust based on training results

// Load Random Forest JSON model
async function loadForest() {
  if (rfForest) return; // already loaded
  const res = await fetch(chrome.runtime.getURL("rf_model.json"));
  rfForest = await res.json();
  console.log("Model loaded with", rfForest.length, "trees");
}

function evalTree(tree, features) {
  if ("value" in tree) {
    return tree.value[1] > tree.value[0] ? 1 : 0;
  }
  const fVal = features[tree.feature];
  return fVal <= tree.threshold
    ? evalTree(tree.left, features)
    : evalTree(tree.right, features);
}

function predictForest(features) {
  const votes = rfForest.map(tree => evalTree(tree, features));
  const voteSum = votes.reduce((a, b) => a + b, 0);
  return voteSum / rfForest.length;
}

function extractFeaturesFromPage() {
  const url = window.location.href.toLowerCase();
  const hostname = new URL(url).hostname;
  const specials = ['%', '-', '=', '&', ';'];
  const keywords = ['login', 'verify', 'secure', 'account', 'signin'];

  const staticFeatures = {
    url_length: url.length,
    dot_count: hostname.split('.').length,
    special_char_count: specials.reduce((acc, ch) => acc + (url.split(ch).length - 1), 0),
    suspicious_keywords: keywords.filter(k => url.includes(k)).length,
    entropy: (() => {
      const counts = {};
      for (const char of hostname) {
        counts[char] = (counts[char] || 0) + 1;
      }
      const len = hostname.length;
      return Object.values(counts).reduce((sum, count) => {
        const p = count / len;
        return sum - p * Math.log2(p);
      }, 0);
    })(),
    has_at: url.includes('@') ? 1 : 0,
    subdomain_length: (() => {
      const parts = hostname.split('.');
      return parts.length >= 3 ? parts.slice(0, -2).join('.').length : 0;
    })(),
    has_hyphen: hostname.includes('-') ? 1 : 0,
    is_ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0
  };

  return staticFeatures; // Dynamic features like eval count, etc., require deeper instrumentation
}

async function getPhishingPrediction() {
  await loadForest();
  const features = extractFeaturesFromPage();
  const probability = predictForest(features);
  const isPhishing = probability >= rfThreshold;

  return {
    probability,
    isPhishing,
    details: isPhishing ? "This page is likely a phishing attempt." : "This page appears safe."
  };
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'GetPrediction') {
    getPhishingPrediction().then(result => sendResponse({ result }));
    return true;
  }
});
