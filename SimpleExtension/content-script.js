(function() {
  console.log("✅ Content script running on", window.location.href);

  function extractFeaturesFromPage() {
    const url      = window.location.href.toLowerCase();
    const hostname = new URL(url).hostname;

    const url_length = url.length;
    const dot_count  = hostname.split('.').length;

    const subdomain_length = (() => {
      const parts = hostname.split('.');
      return parts.length >= 3
        ? parts.slice(0, -2).join('.').length
        : 0;
    })();

    const entropy = (() => {
      const counts = {};
      for (const c of hostname) counts[c] = (counts[c]||0) + 1;
      const len = hostname.length;
      return Object.values(counts).reduce((sum, count) => {
        const p = count/len;
        return sum - p * Math.log2(p);
      }, 0);
    })();

    return { url_length, dot_count, subdomain_length, entropy };
  }

  // Extract features
  const features = extractFeaturesFromPage();

  // Prediction request; the background will cache & respond
  chrome.runtime.sendMessage({ action: "PredictForest", features });
})();
