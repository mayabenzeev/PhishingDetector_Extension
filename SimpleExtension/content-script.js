console.log("✅ Content script running on", window.location.href);

function extractFeaturesFromPage() {
  const url = window.location.href.toLowerCase();
  const hostname = new URL(url).hostname;

  const url_length = url.length;
  const dot_count = hostname.split('.').length;

  const subdomain_length = (() => {
    const parts = hostname.split('.');
    return parts.length >= 3 ? parts.slice(0, -2).join('.').length : 0;
  })();

  const entropy = (() => {
    const counts = {};
    for (const char of hostname) {
      counts[char] = (counts[char] || 0) + 1;
    }
    const len = hostname.length;
    return Object.values(counts).reduce((sum, count) => {
      const p = count / len;
      return sum - p * Math.log2(p);
    }, 0);
  })();

  return {
    url_length,
    dot_count,
    subdomain_length,
    entropy
  };
}

const features = extractFeaturesFromPage();
chrome.runtime.sendMessage({ action: "PredictForest", features }, (response) => {
  if (response?.error) {
    console.warn("❌ Prediction failed:", response.error);
  } else {
    console.log("🧠 Phishing prediction:", JSON.stringify(response, null, 2));
    if (response.isPhishing) {
      document.body.style.border = "5px solid red";
    }
  }
});
