import { loadModel } from './src/onnx.js';

let session = null;
const rfThreshold = 0.58;
const cache = {}; // tabId → { probability, isPhishing }

// Load ONNX model once when background starts
(async () => {
  try {
    session = await loadModel();
    console.log("✅ ONNX model loaded");
  } catch (e) {
    console.error("❌ Failed to load ONNX model", e);
  }
})();

// Helper: Convert feature object to ONNX tensor
function makeTensor(features) {
  const inputArray = Float32Array.from([
    features.url_length,
    features.dot_count,
    features.subdomain_length,
    features.entropy,
  ]);
  return new ort.Tensor("float32", inputArray, [1, 4]);
}

// Listen for messages from content-script and popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "PredictForest" && sender.tab?.id) {
    if (!session) {
      sendResponse({ error: "Model not ready" });
      return true;
    }

    (async () => {
      try {
        const inputName = session.inputNames[0];
        const outputName = session.outputNames[1]; // e.g. output_probability
        const tensor = makeTensor(msg.features);
        const results = await session.run({ [inputName]: tensor });

        const proba = results[outputName].data[1]; // p(class=1)
        const isPhish = proba >= rfThreshold;

        // Cache for popup
        cache[sender.tab.id] = { probability: proba, isPhishing: isPhish };
        console.log(`🧠 Prediction for tab ${sender.tab.id}:`, cache[sender.tab.id]);

        sendResponse({ probability: proba, isPhishing: isPhish });
      } catch (err) {
        console.error("❌ Prediction error:", err);
        sendResponse({ error: err.message });
      }
    })();

    return true; // Async
  }

  if (msg.action === "GetStoredPrediction" && msg.tabId) {
    const res = cache[msg.tabId];
    console.log(`📤 Returning cached prediction for tab ${msg.tabId}:`, res);
    sendResponse(res || { error: "No prediction yet" });
    return false;
  }
});
