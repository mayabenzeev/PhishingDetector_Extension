
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
  
  let score = 0;

  // Subdomain length check:
  // Count how many parts the hostname has (e.g., 'login.mail.example.com' => 4 parts)
  // If there are at least 3 parts - can evaluate subdomain.
  // Extract all parts except the last two (domain and TLD), then check their total length.
  const parts = hostname.split('.');
  if (parts.length >= 3) {
    const subdomainParts = parts.slice(0, parts.length - 2);
    const subdomain = subdomainParts.join('.');
    if (subdomain.length > 5) score += 0.5;
  }

  // Free hosting provider check
  const domain = parts[parts.length - 2].toLowerCase();
  const freeHostingProviders = [
    "000webhost", "freehostia", "neocities", "wordpress",
    "blogspot", "netlify", "weebly", "github", "weeblysite"
  ];
  const isFreeHosting = freeHostingProviders.includes(domain);

  // Hyphen in URL
  const hasHyphenSegments = fullUrl.split('-').length > 1;
  if (isFreeHosting || hasHyphenSegments) score += 0.5;

  // New features:

  // 1. Detect a Long URL
  // Phishing URLs are much longer than legitimate ones - disguise the real domain and include misleading subpaths.
  if (fullUrl.length > 100) score += 1.0;
  else if (fullUrl.length > 75) score += 0.5;

  // 2. Dot count in hostname
  // Large number of dots = deeply nested subdomains that attackers often use to include brand names and hide the real domain.
  const dotCount = hostname.split('.').length;
  if (dotCount > 4) score += 0.7;
  else if (dotCount > 3) score += 0.4;

  // 3. @ symbol in URL
  // URLs with '@' are used to mislead users (e.g., 'paypal.com@phish.com' really goes to 'phish.com') = strong phishing signal.
  if (fullUrl.includes('@')) score += 1.0;

  // 4. Special character count
  //  %, -, =, & chars are used excessively in phishing URLs to encode payloads, parameters or confuse users.
  const specials = ['%', '-', '=', '&', ';'];
  const specialCount = specials.reduce((acc, ch) => acc + (fullUrl.split(ch).length - 1), 0);
  if (specialCount >= 4) score += 1.0;
  else if (specialCount >= 2) score += 0.5;

  // 5. Domain entropy
  // Calculates randomness in the domain name.
  // High entropy = random domains like 'xnqzwdkg.biz' = auto-generated phishing sites.
  score += domainEntropyScore(hostname);

  // 6. Suspicious keywords
  // Find urgent or action based words ('login', 'verify'..) = count how many appear, increase score.
  const keywords = ['login', 'verify', 'secure', 'account', 'signin'];
  const keywordMatches = keywords.filter(k => fullUrl.includes(k));
  score += keywordMatches.length * 0.4;

  return score >= 2 ? 1 : 0;
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