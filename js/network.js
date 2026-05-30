async function testWebSocket() {
    let startTime = Date.now();
    let ws = new WebSocket("./ws");

    ws.onopen = function() {
        ws.send("ping");
    };

    ws.onmessage = function(event) {
        let rtt = Date.now() - startTime;
        document.getElementById("ws_rtt").innerText = event.data;
        ws.close();
    };

    ws.onerror = function() {
        document.getElementById("ws_rtt").innerText = "WebSocket Error";
    };
}

// WebRTC IP 获取并通过POST发送
async function getWebRTCIP() {
    return new Promise((resolve, reject) => {
        let ips = [];
        try {
            let pc = new RTCPeerConnection({
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
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
            // 未获取到
        }

       
        setTimeout(() => resolve(ips.length ? ips : []), 3000);
    });
}

// 发送IP数据到指定端口
async function testIPs() {
    try {
        const ips = await getWebRTCIP();
        
        const response = await fetch(`./ips/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ ips })
        });

        if (!response.ok) {
            console.error("Failed to send IP addresses:", response.statusText);
        }
    } catch (error) {
        // 出错
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
        // 出错
    }
}

// 执行所有的请求并行
async function initializenetwork() {
    try {
        await Promise.all([ testWebSocket(), testIPs()]);
    } catch (error) {
    }
}

// 调用 runTests 来执行并行请求
initializenetwork();
