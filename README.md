# Universal HLS Decryptor & Downloader

A powerful Firefox extension that fully automates the downloading and decryption of AES-128 encrypted HLS (HTTP Live Streaming) video streams (`.m3u8`). It perfectly handles complex streaming platforms that utilize **dynamic key rotation**.

## 🔑 Segment-Level Encryption & Key Rotation

The core challenge this extension solves is dynamic key rotation mid-stream. 
> **Segment-Level Encryption:** Each `#EXT-X-KEY` tag applies to all subsequent `#EXTINF` segments until a new `#EXT-X-KEY` tag is encountered.

### Example M3U8:
```m3u8
#EXTM3U
#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/key.php?id=1"
#EXTINF:10.0,
https://example.com/segment1.ts
#EXTINF:10.0,
https://example.com/segment2.ts
#EXT-X-KEY:METHOD=AES-128,URI="https://example.com/key.php?id=2"
#EXTINF:10.0,
https://example.com/segment3.ts
```
*(In this example, Key 1 decrypts segments 1 and 2. Key 2 decrypts segment 3.)*

## 🛡️ Multi-Layer Key Extraction

To combat DRM and obfuscation, the extension guarantees key acquisition using three fallback strategies:
1. **Direct URI Fetch:** Scrapes auth tokens from local storage and fetches keys directly via HTTP.
2. **Network Sniper:** Intercepts live network traffic to extract raw AES bytes on the fly.
3. **Crypto Hooking:** Injects a CSP-bypassing script to monkey-patch `crypto.subtle.importKey`, capturing keys exactly when the video player uses them.

## 🔥 Key Features
* **In-Browser Decryption:** Merges and decrypts TS segments automatically. No FFmpeg needed.
* **Brute-Force Matcher:** Tests captured keys against segments by verifying the MPEG-TS Sync Byte (`0x47`), ensuring perfect key-to-segment mapping.
* **Web Crypto No-Padding Workaround:** Bypasses strict PKCS7 padding requirements of the Web Crypto API using synthetic padding.

## 🚀 Usage (Firefox)
1. Go to `about:debugging#/runtime/this-firefox`
2. Click **"Load Temporary Add-on..."** and select `manifest.json`.
3. Open any protected video page, open the extension popup, and click **Download**.