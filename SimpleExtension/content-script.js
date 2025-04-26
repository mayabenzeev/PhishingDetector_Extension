
function getPhishingPrediction(){
  const isURL = isDetectedByURL() == 1;
  const isContent = isDetectedByContent() == 1;
  const isPhishing = isURL || isContent;
  return {
    isURL,
    isContent,
    details: isPhishing ? "This page may be a phishing attempt." : "This page seems safe."
  };
}



chrome.runtime.onMessage.addListener((request,sender, sendResponese) => {
  if (request.action ==='GetPrediction'){
    sendResponese({result : getPhishingPrediction()});
  }
});

function isDetectedByURL(){
  const parsedUrl = new URL(window.location.href);
  const hostname = parsedUrl.hostname; // e.g., sub.example.com
  const fullUrl = window.location.href.toLowerCase();
  
  

  // Extract Features
  const url_length = fullUrl.length;
  const dot_count = hostname.split('.').length;
  const specials = ['%', '-', '=', '&', ';'];
  const special_char_count = specials.reduce((acc, ch) => acc + (fullUrl.split(ch).length - 1), 0);

  const keywords = ['login', 'verify', 'secure', 'account', 'signin'];
  const suspicious_keywords = keywords.filter(k => fullUrl.includes(k)).length;

  const counts = {};
  for (const char of hostname) {
    counts[char] = (counts[char] || 0) + 1;
  }
  const len = hostname.length;
  const entropy = Object.values(counts).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);

  // Apply trained model weights:
  const weights = {
    url_length: 6.0156,
    dot_count: 1.8407,
    special_char_count: 0.9769,
    entropy: -2.8668,
    suspicious_keywords: 0.9430,
  };
  const bias = -1.6438;
  const threshold = 0.374;

  const z =
    weights.url_length * url_length +
    weights.dot_count * dot_count +
    weights.special_char_count * special_char_count +
    weights.entropy * entropy +
    weights.suspicious_keywords * suspicious_keywords +
    bias;

  const probability = 1 / (1 + Math.exp(-z));
  return probability > threshold ? 1 : 0;
}
  

// Measures how "random" the domain is by using Shannon entropy.
// If entropy > 4, add 0.5 to the score.
function domainEntropyScore(domain) {
  const counts = {};
  for (const char of domain) {
    counts[char] = (counts[char] || 0) + 1;
  }
  const len = domain.length;
  const entropy = Object.values(counts).reduce((sum, count) => {
    const p = count / len;
    return sum - p * Math.log2(p);
  }, 0);
  return entropy > 4 ? 0.5 : 0;
}

function isDetectedByContent(){
  let score = 0;
  const htmlLength = document.documentElement.outerHTML.length;
  const isHtmlShort = htmlLength < 7500;
  if (isHtmlShort){
    score += 0.35;
  }
  // Condition 2: Check form actions
  const forms = document.querySelectorAll("form");
  let insecureForms = 0;
  forms.forEach(form => {
    const action = form.getAttribute("action");
    if (!action || action.startsWith("http://")) {
      insecureForms++;
    }
  });
  const hasInsecureForm = insecureForms > 0;
  if (hasInsecureForm){
    score += 0.35;
  }
  // Condition 3: Check external images
  const images = document.querySelectorAll("img");
  let externalImages = 0;
  const currentDomain = window.location.hostname;
  images.forEach(img => {
    const src = img.getAttribute("src");
    if (src && src.startsWith("http") && !src.includes(currentDomain)) {
      externalImages++;
    }
  });
  const isFewExternalImages = externalImages <= 5;
  if (isFewExternalImages){
    score += 0.35;
  }

  return Math.min(score,1);
      
}