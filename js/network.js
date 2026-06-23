async function testWebSocket() {
    let startTime = Date.now();
    const runtime = window.__rtCfg__ || {};
    const wsUrl = runtime.wsUrl
        ? runtime.wsUrl()
        : (window.location.protocol === "https:"
            ? `wss://${window.location.host}/socket`
            : `ws://${window.location.host}/socket`);
    let ws = new WebSocket(wsUrl);

    ws.onopen = function() {
        ws.send("ping");
    };

    ws.onmessage = function(event) {
        let rtt = Date.now() - startTime;
        const wsRttNode = document.getElementById("ws_rtt");
        if (wsRttNode) {
            wsRttNode.innerText = event.data;
        }
        ws.close();
    };

    ws.onerror = function() {
        const wsRttNode = document.getElementById("ws_rtt");
        if (wsRttNode) {
            wsRttNode.innerText = "WebSocket Error";
        }
    };
}

async function getWebRTCIP() {
    return new Promise((resolve, reject) => {
        let ips = [];
        try {
            let pc = new RTCPeerConnection({
                iceServers: [{ urls: "stun:stun1.l.google.com:19302" }, { urls: "stun:stun2.l.google.com:19302" }]
            });

            pc.createDataChannel("");
            pc.createOffer().then(offer => pc.setLocalDescription(offer)).catch(err => reject(err));

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    let ipMatch = event.candidate.candidate.match(/\d+\.\d+\.\d+\.\d+/);
                    if (ipMatch && !ips.includes(ipMatch[0])) {
                        ips.push(ipMatch[0]);
                    }
                }
            };
        } catch (error) {
        }

        setTimeout(() => resolve(ips.length ? ips : []), 3000);
    });
}

async function testIPs() {
    try {
        const ips = await getWebRTCIP();
        const runtime = window.__rtCfg__ || {};
        const ipsUrl = runtime.buildHttpUrl
            ? runtime.buildHttpUrl("cdn/analytics/geo")
            : (runtime.ipsUrl ? runtime.ipsUrl() : "./cdn/analytics/geo");

        const response = await fetch(ipsUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ ips })
        });

        if (!response.ok) {
        }
    } catch (error) {
    }
}

function testTcp() {
    try {
        const response = fetch(`http://${window.location.hostname}:80`, {
            method: "POST",
            headers: {
            },
        });

        if (!response.ok) {
        }
    } catch (error) {
    }
}

async function initializenetwork() {
    try {
        await Promise.all([testWebSocket(), testIPs()]);
    } catch (error) {
    }
}

initializenetwork();
