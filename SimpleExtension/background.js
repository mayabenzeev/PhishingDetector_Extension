import predictPhishScore from "./predict_model.js";
console.log(">>> predictPhishScore is", typeof predictPhishScore, predictPhishScore);

const bestThres = 0.14; 
const rfThreshold = 1 - bestThres;
const cache = {}; 

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "PredictForest" && sender.tab?.id) {
    // Pull out the 13 features we trained
    const {entropy, url_length, pageLoadTime, eventListenerCount, subdomain_length, memoryUsed, scriptInjectionCount, domMutationCount, dot_count, fetchCount, xhrCount, is_free_hosting, attributeMutationCount} = msg.features;

    // Call the generated JS function of the Random Forest model to predict the phishing score
    let probability = predictPhishScore([
      entropy, url_length, pageLoadTime, eventListenerCount, subdomain_length, memoryUsed, scriptInjectionCount, domMutationCount, dot_count, fetchCount, xhrCount, is_free_hosting, attributeMutationCount
    ]);

    const isPhishing = probability[1] >= rfThreshold;
    cache[sender.tab.id] = { probability, isPhishing };

    console.log("Received features for prediction:");
    console.log("features:", {url_length, entropy, pageLoadTime, eventListenerCount, subdomain_length});
    console.log("URL:", sender.tab?.url || "(no URL)");
    console.log("Features:", msg.features);
    console.log(`Phishing Probability: ${probability[1]}`);
    console.log(`Benign Probability: ${probability[0]}`);
    console.log(`Classified as Phishing: ${isPhishing}`);

    sendResponse({ probability, isPhishing });
    
  }

  if (msg.action === "GetStoredPrediction") {
    console.log("Getting prediction for tab:", msg.tabId);
    sendResponse(cache[msg.tabId] || { error: "No prediction yet" });
  }

  return true;
});