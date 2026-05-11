// =====================================================
// BACKGROUND.JS - Network Sniper + Crypto Hook + Brute Match
// =====================================================

var authHeaders = {};
var capturedPlaylists = {};
var hookedKeys = [];        // [{hex, data}] - tüm yakalanan key'ler (hook + sniper)
var suspects = [];
var activeTask = { status: "IDLE", progress: 0, text: "" };
var pastedM3U8Text = null;

// ============ NETWORK SNİPER: key byte'larını ağ trafiğinden yakala ============
try {
  browser.webRequest.onBeforeRequest.addListener(
    function (details) {
      // Filter Key URLs (video/key, key/video, video-key, etc.)
      const keyPatterns = [
        'video/key',
        'key/video',
        'video-key',
        'stream-key',
        '/vod/key/',
        'playkey',
        'enckey',
        'key_url'
      ];

      const url = details.url.toLowerCase();
      const isKeyRequest = keyPatterns.some(pattern => url.includes(pattern));

      if (!isKeyRequest) {
        return;
      }

      console.log("🔑 Key request detected:", details.url);

      var filter = browser.webRequest.filterResponseData(details.requestId);
      var chunks = [];

      filter.ondata = function (event) {
        chunks.push(new Uint8Array(event.data));
        filter.write(event.data); // Veriyi olduğu gibi geçir
      };

      filter.onstop = function () {
        filter.disconnect();

        // Parçaları birleştir
        var totalLen = 0;
        for (var i = 0; i < chunks.length; i++) totalLen += chunks[i].length;
        var combined = new Uint8Array(totalLen);
        var offset = 0;
        for (var i = 0; i < chunks.length; i++) {
          combined.set(chunks[i], offset);
          offset += chunks[i].length;
        }

        // JSON hata yanıtlarını atla (0x7b = '{')
        if (combined[0] === 0x7b) {
          console.log("⚠️ Sniper: Skipped JSON response:", details.url.split('/').pop());
          return;
        }

        // 16 byte olmalı (AES-128 key)
        if (combined.length !== 16) {
          console.log("⚠️ Sniper: Unexpected size:", combined.length, "byte");
          // Yine de sakla, belki brute-force bulur
        }

        // Hex'e çevir
        var hex = "";
        for (var i = 0; i < combined.length; i++) {
          var h = combined[i].toString(16);
          hex += (h.length < 2 ? "0" : "") + h;
        }

        // Duplikat kontrolü
        var isDupe = false;
        for (var i = 0; i < hookedKeys.length; i++) {
          if (hookedKeys[i].hex === hex) { isDupe = true; break; }
        }

        if (!isDupe) {
          var keyBuf = combined.buffer.slice(0, 16); // İlk 16 byte
          hookedKeys.push({ hex: hex.substring(0, 32), data: keyBuf, source: "sniper" });
          console.log("🔫 SNİPER KEY #" + hookedKeys.length + ":", hex.substring(0, 32), "(" + details.url.split('/').pop() + ")");
        }
      };

      filter.onerror = function () {
        try { filter.disconnect(); } catch (e) { }
      };
    },
    { urls: ["<all_urls>"] },
    ["blocking"]
  );
  console.log("🔫 Network Sniper active!");
} catch (e) {
  console.warn("filterResponseData unavailable:", e.message);
}

// ============ MESAJ DİNLEYİCİ ============
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  try {
    if (!msg) return false;

    if (msg.type === "FOUND_RESOURCES") {
      if (msg.playlists) {
        for (var i = 0; i < msg.playlists.length; i++) {
          if (msg.playlists[i]) capturedPlaylists[msg.playlists[i]] = { url: msg.playlists[i] };
        }
      }
      if (msg.suspects) {
        for (var i = 0; i < msg.suspects.length; i++) {
          if (msg.suspects[i] && suspects.indexOf(msg.suspects[i]) === -1) suspects.push(msg.suspects[i]);
        }
      }
      return false;
    }

    // Crypto Hook'tan gelen key
    if (msg.type === "CRYPTO_KEY_CAPTURED" && msg.hex) {
      var isDupe = false;
      for (var i = 0; i < hookedKeys.length; i++) {
        if (hookedKeys[i].hex === msg.hex) { isDupe = true; break; }
      }
      if (!isDupe) {
        var bytes = new Uint8Array(16);
        for (var i = 0; i < 16; i++) bytes[i] = parseInt(msg.hex.substr(i * 2, 2), 16);
        hookedKeys.push({ hex: msg.hex, data: bytes.buffer });
        console.log("🎯 HOOK KEY #" + hookedKeys.length + ": " + msg.hex);
      }
      return false;
    }

    if (msg.type === "GET_STATE") {
      sendResponse({
        capturedPlaylists: capturedPlaylists,
        hookKeyCount: hookedKeys.length,
        hookedKeyHexes: hookedKeys.map(function (k) { return k.hex; }),
        suspects: suspects,
        activeTask: activeTask
      });
      return false;
    }

    if (msg.type === "PASTE_M3U8" && msg.text) {
      pastedM3U8Text = msg.text;
      capturedPlaylists["pasted:m3u8"] = { url: "pasted:m3u8" };
      console.log("M3U8 pasted, length:", msg.text.length);
      return false;
    }
    if (msg.type === "START_HARVEST") { startHarvest(msg.url); return false; }
    if (msg.type === "START_DOWNLOAD") { startDownload(msg.url); return false; }
    if (msg.type === "FOUND_TOKENS" && msg.tokens) {
      Object.assign(authHeaders, msg.tokens);
      return false;
    }
  } catch (e) { console.error("BG Error:", e); }
  return false;
});

// ============ ANAHTAR TOPLAMA ============
async function startHarvest(m3u8Url) {
  activeTask = { status: "RUNNING", progress: 0, text: "Analyzing M3U8..." };
  try {
    var text = await getM3U8Text(m3u8Url);
    if (!text || text.indexOf('#EXTM3U') === -1) {
      activeTask = { status: "ERROR", text: "Failed to read M3U8!" };
      return;
    }
    text = text.replace(/\r/g, '');
    var lines = text.split('\n');
    var keyPoints = [];
    var time = 0;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line.indexOf('#EXTINF:') === 0) {
        time += parseFloat(line.split(':')[1].split(',')[0]) || 0;
      } else if (line.indexOf('#EXT-X-KEY') === 0) {
        keyPoints.push({ time: Math.floor(time) + 1, index: keyPoints.length });
      }
    }

    activeTask.text = keyPoints.length + " key points. Waiting for hook...";

    // İlk olarak hook'un enjekte olduğundan emin ol
    await injectContentScript();
    await sleep(1000);

    var beforeCount = hookedKeys.length;

    for (var i = 0; i < keyPoints.length; i++) {
      var prevCount = hookedKeys.length;
      activeTask.text = "Seek: " + (i + 1) + "/" + keyPoints.length + " (sec:" + keyPoints[i].time + ") | Key: " + hookedKeys.length;
      activeTask.progress = Math.round(((i + 1) / keyPoints.length) * 100);

      // Seek + kısa play (player'ın key fetch etmesi için)
      await seekAndPlay(keyPoints[i].time);

      // Key'in gelmesini bekle (max 8 saniye)
      var waitStart = Date.now();
      while (hookedKeys.length <= prevCount && (Date.now() - waitStart) < 8000) {
        await sleep(500);
      }

      if (hookedKeys.length > prevCount) {
        console.log("✅ Key#" + i + " yakalandı (sec:" + keyPoints[i].time + "): " + hookedKeys[hookedKeys.length - 1].hex);
      } else {
        console.log("⏳ Key#" + i + " (sec:" + keyPoints[i].time + ") not captured, continuing...");
      }
    }

    activeTask = {
      status: "DONE", progress: 100,
      text: "Done! " + hookedKeys.length + " keys captured (required: " + keyPoints.length + ")"
    };
  } catch (e) {
    activeTask = { status: "ERROR", text: "Error: " + e.message };
    console.error(e);
  }
}

// ============ İNDİRME & DECRYPT ============
async function startDownload(m3u8Url) {
  activeTask = { status: "RUNNING", progress: 0, text: "Preparing..." };
  try {
    var text = await getM3U8Text(m3u8Url);
    if (!text || text.indexOf('#EXTM3U') === -1) {
      activeTask = { status: "ERROR", text: "Failed to read M3U8! İlk 80 chr: " + (text || "EMPTY").substring(0, 80) };
      return;
    }
    text = text.replace(/\r/g, '');
    var lines = text.split('\n');

    // Parse m3u8
    var keyEntries = [];
    var playlist = [];
    var curKeyIndex = -1;
    var curIV = null;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line.indexOf('#EXT-X-KEY') === 0) {
        var info = parseKeyLine(line, m3u8Url);
        curKeyIndex = keyEntries.length;
        curIV = info.iv;
        keyEntries.push({ uri: info.uri, iv: info.iv });
      } else if (line.length > 0 && line.indexOf('#') !== 0) {
        playlist.push({
          url: line.indexOf('http') === 0 ? line : resolveUrl(line, m3u8Url),
          keyIndex: Math.max(0, curKeyIndex),
          iv: curIV
        });
      }
    }

    console.log("Parse:", keyEntries.length, "key,", playlist.length, "segment");
    activeTask.text = keyEntries.length + " key, " + playlist.length + " segment.";

    if (hookedKeys.length === 0) {
      activeTask = { status: "ERROR", text: "No keys captured! Run 'HARVEST KEYS' first." };
      return;
    }

    activeTask.text = hookedKeys.length + " hook keys for brute-force match...";
    await sleep(1000);

    // Her key grubu için brute-force eşleştirme (no-padding destekli)
    var numGroups = keyEntries.length > 0 ? keyEntries.length : 1;
    var keyGroupMap = {}; // keyIndex -> CryptoKey

    for (var ki = 0; ki < numGroups; ki++) {
      var testSegIdx = -1;
      for (var si = 0; si < playlist.length; si++) {
        if (playlist[si].keyIndex === ki) { testSegIdx = si; break; }
      }
      if (testSegIdx === -1) continue;

      activeTask.text = "Key#" + ki + " test (" + hookedKeys.length + " candidates)...";

      var testSegBuf = await fetchDirect(playlist[testSegIdx].url);
      var testIV = (keyEntries[ki] && keyEntries[ki].iv) || new Uint8Array(16);
      var keyUri = keyEntries[ki] && keyEntries[ki].uri;

      var foundKey = null;
      console.log("🔍 Key#" + ki + " test: seg=" + testSegBuf.byteLength + "b, IV=" + (testIV instanceof Uint8Array ? Array.from(testIV.slice(0, 4)).map(function (b) { return b.toString(16) }).join('') : "null"));

      // YENİ STRATEJİ: Direkt indirmeyi dene (Oturum varsa en garantisi)
      if (keyUri) {
        try {
          console.log("📥 Key#" + ki + " fetching directly: " + keyUri);
          var rawBuf = await fetchDirect(keyUri);
          var rawArr = new Uint8Array(rawBuf);
          // 16 byte ise ve JSON '{' (0x7b) ile başlamıyorsa geçerli bir key'dir
          if (rawArr.length === 16 && rawArr[0] !== 0x7b) {
            var fhex = Array.from(rawArr).map(function (b) { return b.toString(16).padStart(2, '0') }).join('');
            hookedKeys.push({ hex: fhex, data: rawBuf, source: "fetch" });
            console.log("📥 Direct fetch SUCCESSFUL, added to candidates.");
          } else {
            console.log("📥 Direct fetch response invalid (Size:" + rawArr.length + ", First byte:0x" + rawArr[0].toString(16) + ")");
          }
        } catch (err) {
          console.log("📥 Direct fetch error:", err.message);
        }
      }

      for (var ci = 0; ci < hookedKeys.length; ci++) {
        var candidate = hookedKeys[ci];
        console.log("  Candidate " + ci + ": " + candidate.hex + " (" + candidate.data.byteLength + "b)");

        try {
          var cryptoKey = await crypto.subtle.importKey(
            "raw", candidate.data, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]
          );

          // Önce normal padding ile dene
          var decrypted = null;
          try {
            decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv: testIV }, cryptoKey, testSegBuf);
            console.log("    Normal decrypt OK, first byte: 0x" + new Uint8Array(decrypted)[0].toString(16));
          } catch (padErr) {
            console.log("    Normal decrypt error (expected):", padErr.message || padErr.name);
            // No-padding ile dene
            try {
              decrypted = await decryptNoPadding(cryptoKey, testIV, testSegBuf);
              console.log("    NoPadding decrypt OK, first byte: 0x" + new Uint8Array(decrypted)[0].toString(16));
            } catch (noPadErr) {
              console.log("    NoPadding decrypt error too:", noPadErr.message || noPadErr.name);
              continue;
            }
          }

          // TS sync byte kontrolü
          var firstByte = new Uint8Array(decrypted)[0];
          if (firstByte === 0x47) {
            console.log("✅ Key#" + ki + " → " + candidate.hex.substring(0, 8) + " (TS sync OK)");
            keyGroupMap[ki] = cryptoKey;
            foundKey = true;
            break;
          }
        } catch (e) {
          console.log("    importKey/general error:", e.message || e.name);
        }
      }

      if (!foundKey) {
        console.warn("⚠️ Key#" + ki + " mismatched, skipping");
        // DURMA, devam et - diğer key'ler eşleşebilir
      }
    }

    var matchedCount = Object.keys(keyGroupMap).length;
    console.log("Matched: " + matchedCount + "/" + numGroups);

    if (matchedCount === 0) {
      activeTask = { status: "ERROR", text: "No keys matched! (" + hookedKeys.length + " candidates)" };
      return;
    }

    activeTask.text = matchedCount + "/" + numGroups + " keys matched! Starting download...";
    await sleep(1000);

    // Segmentleri indir ve decrypt et
    var segments = [];
    for (var i = 0; i < playlist.length; i++) {
      activeTask.text = "Downloading: " + (i + 1) + "/" + playlist.length;
      activeTask.progress = Math.round(((i + 1) / playlist.length) * 100);

      var segBuf = await fetchDirect(playlist[i].url);
      var keyObj = keyGroupMap[playlist[i].keyIndex];
      var iv = playlist[i].iv || new Uint8Array(16);

      if (!keyObj) {
        console.warn("⚠️ Segment#" + i + " skipping (No valid key found!)");
        continue; // Çöp veri yazmamak için segmenti tamamen atla
      }

      // Decrypt (no-padding destekli)
      var decBuf;
      try {
        decBuf = await crypto.subtle.decrypt({ name: "AES-CBC", iv: iv }, keyObj, segBuf);
      } catch (padErr) {
        decBuf = await decryptNoPadding(keyObj, iv, segBuf);
      }
      segments.push(decBuf);
    }

    // Kaydet
    var blob = new Blob(segments, { type: 'video/mp2t' });
    chrome.downloads.download({
      url: URL.createObjectURL(blob),
      filename: "Decrypted_Video_" + Date.now() + ".ts"
    });
    activeTask = { status: "SUCCESS", text: "✅ Download Complete! (" + playlist.length + " segments, " + (blob.size / 1024 / 1024).toFixed(1) + " MB)" };

  } catch (e) {
    activeTask = { status: "ERROR", text: "Error: " + e.message };
    console.error("Download error:", e);
  }
}

// Web Crypto AES-CBC no-padding workaround
// HLS segmentleri genelde PKCS7 padding içermez ama Web Crypto bunu zorunlu tutar.
// Çözüm: Sentetik padding bloğu ekleyerek Web Crypto'yu kandırıyoruz.
async function decryptNoPadding(key, iv, ciphertext) {
  var ctArray = new Uint8Array(ciphertext);

  // Son 16 byte = son ciphertext bloğu (sentetik padding'in IV'si olacak)
  var lastBlock = ctArray.slice(ctArray.length - 16);

  // 16 byte PKCS7 padding plaintext'i oluştur (her byte = 0x10)
  var paddingPlain = new Uint8Array(16);
  for (var i = 0; i < 16; i++) paddingPlain[i] = 16;

  // Bu padding'i encrypt et (son blok IV olarak kullanılır)
  var encResult = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv: lastBlock },
    key,
    paddingPlain
  );

  // encrypt() kendi padding'ini de ekler (32 byte döner), sadece ilk 16'yı al
  var encPaddingBlock = new Uint8Array(encResult).slice(0, 16);

  // Orijinal ciphertext + sentetik padding bloğu birleştir
  var padded = new Uint8Array(ctArray.length + 16);
  padded.set(ctArray, 0);
  padded.set(encPaddingBlock, ctArray.length);

  // Şimdi decrypt et - Web Crypto valid PKCS7 padding görecek
  var result = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv: iv },
    key,
    padded.buffer
  );

  return result;
}

// ============ YARDIMCI ============

async function getM3U8Text(url) {
  if (url === "pasted:m3u8" && pastedM3U8Text) return pastedM3U8Text;
  try {
    var buf = await fetchDirect(url);
    return new TextDecoder().decode(buf);
  } catch (e) {
    console.warn("M3U8 fetch error:", e.message);
    return null;
  }
}

async function fetchDirect(url) {
  var headers = {};
  try {
    var hostname = new URL(url).hostname;
    if (authHeaders[hostname]) headers['Authorization'] = authHeaders[hostname];
  } catch (e) { }
  var res = await fetch(url, { headers: headers });
  if (!res.ok) throw new Error("HTTP " + res.status);
  return await res.arrayBuffer();
}

async function injectContentScript() {
  var tabs = await new Promise(function (r) { chrome.tabs.query({ active: true, currentWindow: true }, r); });
  if (tabs && tabs[0]) {
    chrome.tabs.executeScript(tabs[0].id, { allFrames: true, file: 'content.js' });
  }
}

async function seekAndPlay(seconds) {
  var tabs = await new Promise(function (r) { chrome.tabs.query({ active: true, currentWindow: true }, r); });
  if (tabs && tabs[0]) {
    chrome.tabs.executeScript(tabs[0].id, {
      allFrames: true,
      code: '(function(){var v=document.querySelector("video");if(v){v.currentTime=' + seconds + ';v.play();setTimeout(function(){v.pause();},2000);}})()'
    });
  }
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

function resolveUrl(relative, base) {
  if (relative.indexOf('http') === 0) return relative;
  if (base.indexOf('pasted:') === 0 || base.indexOf('blob:') === 0) return relative;
  try { return new URL(relative, base).href; } catch (e) { return relative; }
}

function parseKeyLine(line, baseUrl) {
  var uriMatch = line.match(/URI="([^"]+)"/);
  var ivMatch = line.match(/IV=0x([0-9a-fA-F]+)/);
  var uri = uriMatch ? uriMatch[1] : "";
  var ivHex = ivMatch ? ivMatch[1] : null;
  var fullUri = uri.indexOf('http') === 0 ? uri : resolveUrl(uri, baseUrl);
  var iv = null;
  if (ivHex && ivHex.length >= 32) {
    iv = new Uint8Array(16);
    for (var i = 0; i < 16; i++) iv[i] = parseInt(ivHex.substr(i * 2, 2), 16);
  }
  return { uri: fullUri, iv: iv };
}
