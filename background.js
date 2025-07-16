const phishingKeywords = ["login", "secure", "verify", "account", "update", "password", "bank", "paypal"];

function checkUrl(url) {
  if (!url) return false;
  return phishingKeywords.some(keyword => url.toLowerCase().includes(keyword));
}

function alertPhishing(tabId, url) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (url) => alert(`⚠️ Warning: Possible phishing URL detected!\n\n${url}`),
    args: [url]
  }).catch(e => console.error('Injection failed:', e));
}

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (checkUrl(tab.url)) alertPhishing(tabId, tab.url);
  } catch (e) {
    console.error(e);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url && checkUrl(changeInfo.url)) {
    alertPhishing(tabId, changeInfo.url);
  }
});
