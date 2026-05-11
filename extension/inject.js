// inject.js - Crypto hook running in Page context
// This file is loaded directly into the page JS context (via extension URL)

(function () {
    if (window.__hls_decryptor_hooked__) return; // Prevent multiple hooks
    window.__hls_decryptor_hooked__ = true;

    var _origImportKey = crypto.subtle.importKey.bind(crypto.subtle);

    crypto.subtle.importKey = function (format, keyData, algorithm, extractable, usages) {
        try {
            var algoName = "";
            if (typeof algorithm === "string") algoName = algorithm;
            else if (algorithm && algorithm.name) algoName = algorithm.name;

            if (algoName.indexOf("AES") !== -1 && format === "raw") {
                var raw = null;
                if (keyData instanceof ArrayBuffer) {
                    raw = new Uint8Array(keyData);
                } else if (ArrayBuffer.isView(keyData)) {
                    raw = new Uint8Array(keyData.buffer, keyData.byteOffset, keyData.byteLength);
                }

                if (raw && raw.length === 16) {
                    var hex = "";
                    for (var i = 0; i < raw.length; i++) {
                        var h = raw[i].toString(16);
                        hex += (h.length < 2 ? "0" : "") + h;
                    }

                    window.postMessage({
                        type: "__DECRYPTOR_KEY__",
                        hex: hex
                    }, "*");

                    console.log("%c🔑 AES Key Captured: " + hex, "color: #00ff88; font-weight: bold;");
                }
            }
        } catch (e) {
            console.warn("Hook error:", e);
        }

        return _origImportKey(format, keyData, algorithm, extractable, usages);
    };

    console.log("%c🎯 Universal Crypto Hook Active!", "color: #e94560; font-size: 14px; font-weight: bold;");
})();
