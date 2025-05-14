(function () {
  console.log("✅ Content script running on", window.location.href);

  function extractFeaturesFromPage() {
    const url = window.location.href.toLowerCase();
    const hostname = new URL(url).hostname;

    const url_length = url.length;
    const dot_count = (hostname.match(/\./g) || []).length;

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

    const pageLoadTime = (() => {
  const nav = performance.getEntriesByType('navigation')[0];
  return nav ? performance.now() - nav.domContentLoadedEventEnd : 0;
})();


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
        url_length: parseFloat(url_length),
        entropy: parseFloat(entropy),
        dot_count: parseFloat(dot_count),
        subdomain_length: parseFloat(subdomain_length),
        pageLoadTime: parseFloat(pageLoadTime),
        eventListenerCount: parseFloat(eventListenerCount),
        memoryUsed: parseFloat(memoryUsed)
      };

  }

  const features = extractFeaturesFromPage();
  console.log("📤 Sending PredictForest from content script:", features);
  chrome.runtime.sendMessage({ action: "PredictForest", features });
})();
