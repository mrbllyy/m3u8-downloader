document.addEventListener('DOMContentLoaded', function() {
    var list = document.getElementById('playlist-list');
    var suspectList = document.getElementById('suspect-list');
    var statusText = document.getElementById('status-text');
    var progressSection = document.getElementById('progress-section');
    var progressBar = document.getElementById('progress-bar');

    setInterval(updateUI, 1000);
    updateUI();

    function updateUI() {
        chrome.runtime.sendMessage({ type: "GET_STATE" }, function(state) {
            if (chrome.runtime.lastError || !state) return;

            if (state.capturedPlaylists) renderPlaylists(state.capturedPlaylists);
            if (state.suspects) renderSuspects(state.suspects);

            // Hook key counter
            var keyInfo = document.getElementById('key-info');
            if (keyInfo) {
                var count = state.hookKeyCount || 0;
                keyInfo.innerText = "🎯 Captured Keys: " + count + "/9";
                
                if (count >= 9) {
                    keyInfo.style.color = "#00ff88";
                    keyInfo.style.background = "#0a2a1a";
                } else if (count > 0) {
                    keyInfo.style.color = "#ffaa00";
                } else {
                    keyInfo.style.color = "#e94560";
                }

                // Show key hexes on hover
                if (state.hookedKeyHexes && state.hookedKeyHexes.length > 0) {
                    var tip = "";
                    for (var i = 0; i < state.hookedKeyHexes.length; i++) {
                        tip += "K" + i + ": " + state.hookedKeyHexes[i] + "\n";
                    }
                    keyInfo.title = tip;
                }
            }

            if (state.activeTask && state.activeTask.status !== "IDLE") {
                progressSection.classList.remove('hidden');
                statusText.innerText = state.activeTask.text || "...";
                progressBar.style.width = (state.activeTask.progress || 0) + "%";
                
                if (state.activeTask.status === "SUCCESS") {
                    progressBar.style.background = "#00ff88";
                } else if (state.activeTask.status === "ERROR") {
                    progressBar.style.background = "#ff4444";
                } else {
                    progressBar.style.background = "";
                }
            }
        });
    }

    document.getElementById('scan-page-btn').onclick = function() {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs && tabs[0]) chrome.tabs.executeScript(tabs[0].id, { file: 'content.js', allFrames: true });
        });
    };

    document.getElementById('seek-btn').onclick = function() {
        chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
            if (tabs && tabs[0]) chrome.tabs.executeScript(tabs[0].id, {
                allFrames: true,
                code: 'if(document.querySelector("video")){document.querySelector("video").currentTime += 300;}'
            });
        });
    };

    function renderPlaylists(playlists) {
        var keys = Object.keys(playlists);
        for (var i = 0; i < keys.length; i++) {
            var p = playlists[keys[i]];
            if (!p || !p.url || document.querySelector('[data-url="' + p.url + '"]')) continue;
            
            var empty = document.querySelector('.empty-state');
            if (empty) empty.remove();

            var li = document.createElement('li');
            li.className = 'playlist-item';
            li.setAttribute('data-url', p.url);
            var id = p.url === "pasted:m3u8" ? "Pasted M3U8" : p.url.split('/').slice(-2).join('/');
            if (id.length > 35) id = "..." + id.substring(id.length - 32);
            
            li.innerHTML = '<div class="playlist-info"><span class="video-name">🎬 ' + id + '</span></div>'
                + '<div class="btn-group">'
                + '<button class="harvest-btn">🔑 HARVEST KEYS</button>'
                + '<button class="download-btn-pro">⬇️ DOWNLOAD</button>'
                + '</div>';
            
            (function(url) {
                li.querySelector('.harvest-btn').onclick = function() { chrome.runtime.sendMessage({ type: "START_HARVEST", url: url }); };
                li.querySelector('.download-btn-pro').onclick = function() { chrome.runtime.sendMessage({ type: "START_DOWNLOAD", url: url }); };
            })(p.url);
            
            list.appendChild(li);
        }
    }

    function renderSuspects(suspects) {
        if (!suspects || suspects.length === 0) return;
        suspectList.innerHTML = '';
        for (var i = 0; i < suspects.length; i++) {
            if (!suspects[i]) continue;
            var li = document.createElement('li');
            li.className = 'suspect-item';
            li.innerHTML = '<span>📄 ' + suspects[i].split('/').pop().split('?')[0] + '</span>';
            li.title = suspects[i];
            suspectList.appendChild(li);
        }
    }

    document.getElementById('toggle-paste-btn').onclick = function() {
        document.getElementById('paste-section').classList.toggle('hidden');
    };
    document.getElementById('process-paste-btn').onclick = function() {
        var content = document.getElementById('m3u8-content').value.trim();
        if (content.indexOf('#EXTM3U') !== -1) {
            chrome.runtime.sendMessage({ type: "PASTE_M3U8", text: content });
            document.getElementById('paste-section').classList.add('hidden');
        }
    };
});
