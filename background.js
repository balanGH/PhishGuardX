// background.js — Service Worker
console.log("🧠 PhishGuardX Service Worker Active");

const BACKEND_URL = "http://10.5.177.63:5001/analyze"; // change to your backend endpoint

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "feature_extraction") {
    console.log("📩 Received Features from", sender.tab?.url);
    console.log("🧩 Extracted Data:", msg.data);

    // Optional: Send to backend for analysis
    sendToBackend(msg.url, msg.data)
      .then(result => {
        console.log("✅ Backend response:", result);
        sendResponse({ status: "ok", result });
      })
      .catch(err => {
        console.error("❌ Backend error:", err);
        sendResponse({ status: "error", error: err.message });
      });

    return true; // Keep message channel open for async response
  }
});

// Send extracted features to backend
async function sendToBackend(url, data) {
  const payload = { url, features: data };
  const res = await fetch(BACKEND_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!res.ok) throw new Error(`Backend returned ${res.status}`);
  return res.json();
}
