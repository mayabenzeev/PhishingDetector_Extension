import predictPhishScore from "./predict_model.js";

const rfThreshold = 0.9; // TODO: Adjust this threshold based on your model's performance in the jupyter notebook
const cache = {}; 

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "PredictForest" && sender.tab?.id) {
    // Pull out the 7 features we trained
    const { url_length, entropy, subdomain_length, pageLoadTime, dot_count, eventListenerCount, memoryUsed } = msg.features;

    // Call the generated JS function of the Random Forest model to predict the phishing score
    let probability = predictPhishScore([
      url_length,
      entropy,
      dot_count,
      subdomain_length,
      pageLoadTime,
      eventListenerCount,
      memoryUsed
    ]);

    const isPhishing = probability[1] >= rfThreshold;
    cache[sender.tab.id] = { probability, isPhishing };

    console.log("📡 Received features for prediction:");
    console.log("🌐 URL:", sender.tab?.url || "(no URL)");
    console.log("🧮 Features:", msg.features);
    console.log(`🔍 Predicted Probability: ${probability}`);
    console.log(`🚨 Classified as Phishing: ${isPhishing}`);

    sendResponse({ probability, isPhishing });
    
  }

  if (msg.action === "GetStoredPrediction") {
    console.log("📦 Getting prediction for tab:", msg.tabId);
    sendResponse(cache[msg.tabId] || { error: "No prediction yet" });
  }

  return true;
});