let rfForest = null;
const rfThreshold = 0.58;
const cache = {};

fetch(chrome.runtime.getURL("rf_model.json"))
  .then(res => res.json())
  .then(data => {
    rfForest = data;
    console.log("✅ Random Forest model loaded:", rfForest.length, "trees");
  })
  .catch(err => console.error("❌ Failed to load model:", err));

function evalTree(tree, features) {
  if ("value" in tree) return tree.value[1] > tree.value[0] ? 1 : 0;
  const val = features[tree.feature];
  if (val === undefined) {
    throw new Error(`Missing feature: ${tree.feature}`);
  }
  return val <= tree.threshold
    ? evalTree(tree.left, features)
    : evalTree(tree.right, features);
}

function predictForest(features) {
  console.log("📦 Received features for prediction:", features);
  const votes = rfForest.map(tree => evalTree(tree, features));
  const sum = votes.reduce((a,b)=>a+b,0);
  console.log("sum, avg:", sum, sum / rfForest.length);
  return sum / rfForest.length;
}

chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {
  console.log("📩 Background received a message:", req);

  if (req.action === "PredictForest") {
    console.log("📬 Handling PredictForest");

    if (!rfForest) {
      console.warn("⛔ Model not ready");
      sendResponse({ error: "Model not ready" });
      return true;
    }

    try {
      const prob = predictForest(req.features);
      const isPhish = prob >= rfThreshold;
      cache[sender.tab.id] = { probability: prob, isPhishing: isPhish };
      console.log("📈 Prediction result:", { probability: prob, isPhish });
      sendResponse({ probability: prob, isPhishing: isPhish });

    } catch (err) {
      console.error("❌ Prediction error:", err.message);
      sendResponse({ error: err.message });
    }

    return true; // IMPORTANT for async sendResponse
  }

  if (req.action === "GetPrediction") {
    console.log("📤 Popup requested latest prediction");
    const res = cache[req.tabId];
    sendResponse(res || { error: "No prediction available yet" });
    return false;
  }
});
