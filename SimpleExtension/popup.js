document.addEventListener('DOMContentLoaded', () => {
  // Query the active tab to get its ID
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]) return;
    const tabId = tabs[0].id;

    // send your GetPrediction to the background, including tabId
    chrome.runtime.sendMessage(
      { action: 'GetPrediction', tabId },
      (response) => {
        const resultEl = document.getElementById('result');

        if (chrome.runtime.lastError || !response || response.error) {
          console.warn('chrome.runtime.lastError:', chrome.runtime.lastError);
          console.warn('response:', response);
          resultEl.textContent = 'Error retrieving classification.';
          return;
        }

        const { probability, isPhishing } = response;
        resultEl.innerHTML = `
          <div class="${isPhishing ? 'phishing' : 'safe'}">
            <strong>${isPhishing ? "Phishing Detected" : "Safe Page"}</strong>
          </div>
        `;
      }
    );
  });
});
