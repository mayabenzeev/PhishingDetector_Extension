// content-script.js
(function () {
  console.log("Content script running on", window.location.href);

  function extractFeaturesFromPage() {
    const url = window.location.href.toLowerCase();
    const hostname = new URL(url).hostname;

    // 1. Static URL features
    const url_length = url.length;
    const dot_count = (hostname.match(/\./g) || []).length;
    const has_hyphen = hostname.includes('-') ? 1 : 0;
    const freeHosts = [
      "000webhost","freehostia","neocities","wordpress",
      "blogspot","netlify","weebly","github","weeblysite"
    ];
    const parts = hostname.split('.');
    const domain = parts.slice(-2)[0];
    const is_free_hosting = freeHosts.includes(domain) ? 1 : 0;
    const subdomain_length = parts.length >= 3
      ? parts.slice(0, -2).join('.').length
      : 0;

    // 2. Entropy of hostname
    const entropy = (() => {
      const counts = {};
      for (const c of hostname) counts[c] = (counts[c] || 0) + 1;
      const L = hostname.length;
      return Object.values(counts).reduce((sum, f) => {
        const p = f / L;
        return sum - p * Math.log2(p);
      }, 0);
    })();

    // 3. Performance & memory
    const pageLoadTime = (() => {
      const nav = performance.getEntriesByType('navigation')[0];
      return nav ? performance.now() - nav.domContentLoadedEventEnd : 0;
    })();
    const memoryUsed = performance.memory
      ? performance.memory.usedJSHeapSize
      : 0;

    // 4. Event listeners
    const eventListenerCount = (() => {
      let count = 0;
      const props = Object.getOwnPropertyNames(window);
      for (const p of props) {
        if (p.startsWith("on") && typeof window[p] === "function") {
          count++;
        }
      }
      return count;
    })();

    // 5. Dynamic instrumentation (from injected init script)
    const fetchCount               = window.__fetchCount || 0;
    const xhrCount                 = window.__xhrCount || 0;
    const scriptInjectionCount     = window.__scriptInjectionCount || document.getElementsByTagName('script').length;
    const domMutationCount         = window.__domMutationCount || 0;
    const attributeMutationCount   = window.__attributeMutationCount || 0;

    return {
      entropy:               parseFloat(entropy),
      url_length:            parseFloat(url_length),
      pageLoadTime:          parseFloat(pageLoadTime),
      eventListenerCount:    parseFloat(eventListenerCount),
      subdomain_length:      parseFloat(subdomain_length),
      memoryUsed:            parseFloat(memoryUsed),
      scriptInjectionCount:  parseFloat(scriptInjectionCount),
      domMutationCount:      parseFloat(domMutationCount),
      dot_count:             parseFloat(dot_count),
      fetchCount:            parseFloat(fetchCount),
      xhrCount:              parseFloat(xhrCount),
      is_free_hosting:       parseFloat(is_free_hosting),
      attributeMutationCount:parseFloat(attributeMutationCount),
      // has_hyphen:            parseFloat(has_hyphen)
    };
  }

  const features = extractFeaturesFromPage();
  console.log("sending PredictForest from content script:", features);
  chrome.runtime.sendMessage({ action: "PredictForest", features });
})();
