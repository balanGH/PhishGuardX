// URL & Heuristic Feature Extraction - Content Script

(function () {
  // 1. URL-Based Features
  const currentUrl = new URL(window.location.href);
  const urlFeatures = {
    url_length: currentUrl.href.length,
    num_dots: currentUrl.hostname.split('.').length - 1,
    num_subdomains: currentUrl.hostname.split('.').length - 2,
    has_at_symbol: currentUrl.href.includes("@"),
    has_hyphen_in_domain: currentUrl.hostname.includes("-"),
    uses_https: currentUrl.protocol === "https:",
    is_ip_address: /^\d{1,3}(\.\d{1,3}){3}$/.test(currentUrl.hostname),
    uses_nonstandard_port:
      currentUrl.port && currentUrl.port !== "80" && currentUrl.port !== "443"
  };

  // 2. HTML/DOM Features
  const domFeatures = {
    has_iframe: document.querySelectorAll("iframe").length > 0,
    has_password_input: document.querySelectorAll("input[type='password']").length > 0,
    has_inline_script: Array.from(document.scripts).some(script => script.innerText.trim().length > 0),
    anchor_text_mismatch: Array.from(document.querySelectorAll("a")).some(
      a => a.textContent.trim() && a.href && !a.href.includes(a.textContent.trim())
    ),
    external_favicon: (() => {
      const favicon = document.querySelector("link[rel*='icon']");
      return favicon ? !favicon.href.includes(location.hostname) : false;
    })()
  };

  // 3. Behaviour Monitoring (basic flags)
  const behaviourFeatures = {
    right_click_blocked: !!document.oncontextmenu,
    has_popups: !!window.open
  };

  // Combine all features
  const finalFeatures = { ...urlFeatures, ...domFeatures, ...behaviourFeatures };

  // Send features to background service worker
  chrome.runtime.sendMessage({
    type: "feature_extraction",
    url: window.location.href,
    data: finalFeatures
  });

  console.log("🔍 Extracted Features:", finalFeatures);
})();
