let rfForest = null;
const rfThreshold = 0.58;

// Load the model once on startup
fetch(chrome.runtime.getURL("rf_model.json"))
  .then(res => res.json())
  .then(data => {
    rfForest = data;
    console.log("Random Forest loaded:", rfForest.length, "trees");
  })
  .catch(err => console.error("Failed to load model:", err));

function evalTree(tree, features) {
  if ("value" in tree) return tree.value[1] > tree.value[0] ? 1 : 0;
  return features[tree.feature] <= tree.threshold
    ? evalTree(tree.left, features)
    : evalTree(tree.right, features);
}

function predictForest(features) {
  const votes = rfForest.map(tree => evalTree(tree, features));
  return votes.reduce((a, b) => a + b, 0) / rfForest.length;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "PredictForest") {
    if (!rfForest) return sendResponse({ error: "Model not ready" });

    const probability = predictForest(request.features);
    const isPhishing = probability >= rfThreshold;
    sendResponse({ probability, isPhishing });
  }
});
