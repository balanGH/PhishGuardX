const phishingKeywords = ["login", "secure", "verify", "account", "update", "password", "bank", "paypal"];

document.getElementById('scanBtn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) {
      displayResult('No active tab found.', 'orange');
      return;
    }
    const url = tabs[0].url.toLowerCase();
    const foundKeywords = phishingKeywords.filter(keyword => url.includes(keyword));

    if (foundKeywords.length > 0) {
      displayResult(`⚠️ Warning: Suspicious keywords detected (${foundKeywords.join(', ')})!`, 'red');
    } else {
      displayResult('URL looks safe.', 'green');
    }
  });
});

function displayResult(message, color) {
  const resultDiv = document.getElementById('result');
  resultDiv.textContent = message;
  resultDiv.style.color = color;
}
