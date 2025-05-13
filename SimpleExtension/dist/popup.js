document.addEventListener("DOMContentLoaded",()=>{chrome.tabs.query({active:!0,currentWindow:!0},r=>{if(!r[0])return;const i=r[0].id;chrome.runtime.sendMessage({action:"GetStoredPrediction",tabId:i},e=>{const t=document.getElementById("result");if(chrome.runtime.lastError||!e||e.error){console.warn("chrome.runtime.lastError:",chrome.runtime.lastError),console.warn("response:",e),t.textContent="Error retrieving classification.";return}const{probability:o,isPhishing:n}=e;t.innerHTML=`
          <div class="${n?"phishing":"safe"}">
            <strong>${n?"Phishing Detected":"Safe Page"}</strong>
          </div>
        `})})});
