importScripts(chrome.runtime.getURL("ort.min.js"));
// point the runtime at the local WASM file
ort.env.wasm.wasmPaths = [ chrome.runtime.getURL("") ];
// limit threads if you want
ort.env.wasm.numThreads = 1;


let session = null;
const rfThreshold = 0.58;
const cache = {}; // per-tab cache

// // Load ONNX once, on extension install
// chrome.runtime.onInstalled.addListener(async () => {
//   try {
//     const url = chrome.runtime.getURL("rf_model.onnx");
//     const resp = await fetch(url);
//     const bytes  = await resp.arrayBuffer();
//     session = await ort.InferenceSession.create(bytes);
//     console.log("✅ ONNX model loaded");
//   } catch (e) {
//     console.error("❌ Failed to load ONNX model", e);
//   }
// });

(async () => {
  try {
    const url = chrome.runtime.getURL("rf_model.onnx");
    const resp = await fetch(url);
    const bytes = await resp.arrayBuffer();
    session = await ort.InferenceSession.create(bytes);
    console.log("✅ ONNX model loaded");
  } catch (e) {
    console.error("❌ Failed to load ONNX model", e);
  }
})();

// Helper: pack your 4 features into a tensor
function makeTensor(features) {
  // Order must match your Python export
  const arr = Float32Array.from([
    features.url_length,
    features.dot_count,
    features.subdomain_length,
    features.entropy
  ]);
  return new ort.Tensor("float32", arr, [1, 4]);
}

// Listen for predict & cache replies
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Content-script fires on page load:
  if (msg.action === "PredictForest" && sender.tab?.id) {
    if (!session) {
      return sendResponse({ error: "Model not yet ready" });
    }
    (async () => {
      try {
        const inputName  = session.inputNames[0];
        const outputNames = session.outputNames;
        const tensor     = makeTensor(msg.features);
        const results    = await session.run({ [inputName]: tensor });
        // Assume second output is probabilities: [ [p(0),p(1)] ]
        const proba      = results[outputNames[1]].data[1];
        const isPhish    = proba >= rfThreshold;
        cache[sender.tab.id] = { probability: proba, isPhishing: isPhish };
        sendResponse({ probability: proba, isPhishing: isPhish });
      } catch (err) {
        sendResponse({ error: err.message });
      }
    })();
    return true;  // keep channel open for async sendResponse
  }

  // Popup asks for the latest cached result:
  if (msg.action === "GetStoredPrediction") {
    const res = cache[msg.tabId];
    sendResponse(res || { error: "No prediction yet" });
    return false;
  }
});
