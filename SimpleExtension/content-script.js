(function () {
  console.log("✅ Content script running on", window.location.href);

  function extractFeaturesFromPage() {
    const url = window.location.href.toLowerCase();
    const hostname = new URL(url).hostname;

    const url_length = url.length;
    const dot_count = hostname.split('.').length;

    const subdomain_length = (() => {
      const parts = hostname.split('.');
      return parts.length >= 3
        ? parts.slice(0, -2).join('.').length
        : 0;
    })();

    const entropy = (() => {
      const counts = {};
      for (const c of hostname) counts[c] = (counts[c] || 0) + 1;
      const len = hostname.length;
      return Object.values(counts).reduce((sum, count) => {
        const p = count / len;
        return sum - p * Math.log2(p);
      }, 0);
    })();

    const pageLoadTime = performance.timing.loadEventEnd && performance.timing.navigationStart
      ? performance.timing.loadEventEnd - performance.timing.navigationStart
      : 0;

    const eventListenerCount = (() => {
      let total = 0;
      const props = Object.getOwnPropertyNames(window);
      props.forEach(prop => {
        if (prop.startsWith("on") && typeof window[prop] === "function") {
          total += 1;
        }
      });
      return total;
    })();

    const memoryUsed = performance.memory
      ? performance.memory.usedJSHeapSize
      : 0;

    return {
      url_length,
      entropy,
      subdomain_length,
      pageLoadTime,
      dot_count,
      eventListenerCount,
      memoryUsed
    };
  }

  const features = extractFeaturesFromPage();

  chrome.runtime.sendMessage({ action: "PredictForest", features });
})();
