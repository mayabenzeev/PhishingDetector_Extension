// content-script.js (Random Forest only)
let rfForest = null;
const rfThreshold = 0.58; 

// Load Random Forest JSON model
async function loadForest() {
  if (rfForest) return; // already loaded
  const res = await fetch(chrome.runtime.getURL("rf_model.json"));
  rfForest = await res.json();
  console.log(rfForest);
}


function evalTree(tree, features) {
  if ("value" in tree) {
    return tree.value[1] > tree.value[0] ? 1 : 0;
  }
  const fVal = features[tree.feature];
  if (fVal <= tree.threshold) {
    return evalTree(tree.left, features);
  } else {
    return evalTree(tree.right, features);
  }
}

function predictForest(features) {
  const votes = rfForest.map(tree => evalTree(tree, features));
  const voteSum = votes.reduce((a, b) => a + b, 0);
  return voteSum / rfForest.length;
}

async function getPhishingPrediction() {
  await loadForest();

  const parsedUrl = new URL(window.location.href);
  const hostname = parsedUrl.hostname;
  const fullUrl = window.location.href.toLowerCase();

  // Extract features (make sure these match model input names)
  const specials = ['%', '-', '=', '&', ';'];
  const keywords = ['login', 'verify', 'secure', 'account', 'signin'];

  const features = {
    url_length: fullUrl.length,
    dot_count: hostname.split('.').length,
    special_char_count: specials.reduce((acc, ch) => acc + (fullUrl.split(ch).length - 1), 0),
    suspicious_keywords: keywords.filter(k => fullUrl.includes(k)).length,
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
    })()
  };

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
