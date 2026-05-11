// content.js - Injects inject.js into the page and forwards messages to background

// 1. Inject inject.js into page context (extension URL = CSP bypass)
try {
    var s = document.createElement('script');
    s.src = chrome.runtime.getURL('inject.js');
    s.onload = function() { this.remove(); };
    (document.head || document.documentElement).appendChild(s);
} catch(e) {
    console.log("inject.js load error:", e);
}

// 2. Forward key messages from Page to background
window.addEventListener("message", function(event) {
    if (event.data && event.data.type === "__DECRYPTOR_KEY__") {
        try {
            chrome.runtime.sendMessage({
                type: "CRYPTO_KEY_CAPTURED",
                hex: event.data.hex,
                timestamp: Date.now()
            });
        } catch(e) {}
    }
});

// 3. Page scraping (after DOMContentLoaded)
if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(scrapeEverything, 500);
} else {
    document.addEventListener("DOMContentLoaded", function() {
        setTimeout(scrapeEverything, 500);
    });
}

function scrapeEverything() {
    var foundPlaylists = [];
    var suspects = [];
    try {
        var resources = performance.getEntriesByType('resource');
        for (var i = 0; i < resources.length; i++) {
            var url = resources[i].name;
            if (url.indexOf('.m3u8') !== -1 && foundPlaylists.indexOf(url) === -1) foundPlaylists.push(url);
        }
    } catch(e) {}

    // Search for Auth token
    try {
        var tokens = {};
        var authRegex = /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g;
        [localStorage, sessionStorage].forEach(function(storage) {
            for (var i = 0; i < storage.length; i++) {
                var val = storage.getItem(storage.key(i));
                if (typeof val === 'string') {
                    var match = val.match(authRegex);
                    if (match) tokens[location.hostname] = "Bearer " + match[0];
                }
            }
        });
        if (Object.keys(tokens).length > 0) {
            chrome.runtime.sendMessage({ type: "FOUND_TOKENS", tokens: tokens });
        }
    } catch(e) {}

    try {
        chrome.runtime.sendMessage({
            type: "FOUND_RESOURCES",
            playlists: foundPlaylists,
            suspects: suspects
        });
    } catch(e) {}
}

chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
    if (msg && msg.type === "SCAN_PAGE") {
        scrapeEverything();
        sendResponse({ success: true });
    }
    return false;
});
