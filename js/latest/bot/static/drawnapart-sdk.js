(function() {
    'use strict';

    const CONFIG = {
        endpoint: (document.currentScript && document.currentScript.dataset.endpoint) || '/info',
        numOfVertices: 5,
        rounds: 3,
        timeout: 8000,
        sendOnComplete: true
    };

    function buildWorkerCode(config) {
        var code = [];
        code.push('(async function() {');
        code.push('    var numOfVertices = ' + config.numOfVertices + ';');
        code.push('    var stallVertexIdLocation, gl, offscreenCan;');
        code.push('');
        code.push('    var fragment_code = "#version 300 es\\n" +');
        code.push('        "precision mediump float;\\n" +');
        code.push('        "flat in float v_stall;\\n" +');
        code.push('        "out vec4 outColor;\\n" +');
        code.push('        "void main(void) { outColor = vec4(v_stall, 0.0, 0.0, 1.0); }\\n";');
        code.push('');
        code.push('    var vertex_code = "#version 300 es\\n" +');
        code.push('        "uniform int cur_stalled_vertex;\\n" +');
        code.push('        "flat out float v_stall;\\n" +');
        code.push('        "float stall_function() {\\n" +');
        code.push('        "  float res = 0.01;\\n" +');
        code.push('        "  for(int i = 1; i < 65535; i++) { res = sinh(res); }\\n" +');
        code.push('        "  return res;\\n" +');
        code.push('        "}\\n" +');
        code.push('        "void main(void) {\\n" +');
        code.push('        "  if ((cur_stalled_vertex & (1 << gl_VertexID)) != 0) {\\n" +');
        code.push('        "    v_stall = stall_function();\\n" +');
        code.push('        "    gl_Position = vec4(v_stall, 0.0, 1.0, 1.0);\\n" +');
        code.push('        "  } else {\\n" +');
        code.push('        "    v_stall = 0.0;\\n" +');
        code.push('        "    gl_Position = vec4(0.0, 0.0, 1.0, 1.0);\\n" +');
        code.push('        "  }\\n" +');
        code.push('        "  gl_PointSize = 1.0;\\n" +');
        code.push('        "}\\n";');
        code.push('');
        code.push('    function prepareToDraw(gl, vertexCount) {');
        code.push('        var vertices = new Array(vertexCount * 2).fill(0);');
        code.push('        var vertex_buffer = gl.createBuffer();');
        code.push('        gl.bindBuffer(gl.ARRAY_BUFFER, vertex_buffer);');
        code.push('        gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(vertices), gl.STATIC_DRAW);');
        code.push('');
        code.push('        var vertShader = gl.createShader(gl.VERTEX_SHADER);');
        code.push('        gl.shaderSource(vertShader, vertex_code);');
        code.push('        gl.compileShader(vertShader);');
        code.push('        if (!gl.getShaderParameter(vertShader, gl.COMPILE_STATUS)) {');
        code.push('            throw new Error("Vertex shader compile failed: " + gl.getShaderInfoLog(vertShader));');
        code.push('        }');
        code.push('');
        code.push('        var fragShader = gl.createShader(gl.FRAGMENT_SHADER);');
        code.push('        gl.shaderSource(fragShader, fragment_code);');
        code.push('        gl.compileShader(fragShader);');
        code.push('        if (!gl.getShaderParameter(fragShader, gl.COMPILE_STATUS)) {');
        code.push('            throw new Error("Fragment shader compile failed: " + gl.getShaderInfoLog(fragShader));');
        code.push('        }');
        code.push('');
        code.push('        var shaderProgram = gl.createProgram();');
        code.push('        gl.attachShader(shaderProgram, vertShader);');
        code.push('        gl.attachShader(shaderProgram, fragShader);');
        code.push('        gl.linkProgram(shaderProgram);');
        code.push('        if (!gl.getProgramParameter(shaderProgram, gl.LINK_STATUS)) {');
        code.push('            throw new Error("Program link failed: " + gl.getProgramInfoLog(shaderProgram));');
        code.push('        }');
        code.push('        gl.useProgram(shaderProgram);');
        code.push('        gl.bindBuffer(gl.ARRAY_BUFFER, vertex_buffer);');
        code.push('');
        code.push('        var coord = gl.getAttribLocation(shaderProgram, "coordinates");');
        code.push('        if (coord >= 0) {');
        code.push('            gl.vertexAttribPointer(coord, 2, gl.FLOAT, false, 0, 0);');
        code.push('            gl.enableVertexAttribArray(coord);');
        code.push('        }');
        code.push('        stallVertexIdLocation = gl.getUniformLocation(shaderProgram, "cur_stalled_vertex");');
        code.push('    }');
        code.push('');
        code.push('    async function measureVertex(gl, vertexMask) {');
        code.push('        gl.uniform1i(stallVertexIdLocation, vertexMask);');
        code.push('        gl.drawArrays(gl.POINTS, 0, numOfVertices);');
        code.push('        var beforeRender = performance.now();');
        code.push('        await offscreenCan.convertToBlob();');
        code.push('        var afterRender = performance.now();');
        code.push('        return afterRender - beforeRender;');
        code.push('    }');
        code.push('');
        code.push('    async function go(gl) {');
        code.push('        var traces = [];');
        code.push('        for (var vertexMask = 0; vertexMask < (1 << numOfVertices); vertexMask++) {');
        code.push('            traces.push(await measureVertex(gl, vertexMask));');
        code.push('        }');
        code.push('        return traces;');
        code.push('    }');
        code.push('');
        code.push('    async function prepareAndGo() {');
        code.push('        offscreenCan = new OffscreenCanvas(1, 1);');
        code.push('        gl = offscreenCan.getContext("webgl2", { antialias: false });');
        code.push('        if (!gl) throw new Error("WebGL2 not supported");');
        code.push('        prepareToDraw(gl, numOfVertices);');
        code.push('        gl.uniform1i(stallVertexIdLocation, 0);');
        code.push('        gl.drawArrays(gl.POINTS, 0, numOfVertices);');
        code.push('        await offscreenCan.convertToBlob();');
        code.push('        return go(gl);');
        code.push('    }');
        code.push('');
        code.push('    onmessage = async function(e) {');
        code.push('        try {');
        code.push('            var results = [];');
        code.push('            for (var i = 0; i < ' + config.rounds + '; i++) {');
        code.push('                results = results.concat(await prepareAndGo());');
        code.push('            }');
        code.push('            if (gl && gl.getExtension("WEBGL_lose_context")) {');
        code.push('                gl.getExtension("WEBGL_lose_context").loseContext();');
        code.push('            }');
        code.push('            postMessage({ success: true, trace: results });');
        code.push('        } catch (err) {');
        code.push('            postMessage({ success: false, error: err.message || "Unknown error" });');
        code.push('        }');
        code.push('    };');
        code.push('})();');
        return code.join('\n');
    }

    window.DrawnApartSDK = {
        collect: function(customConfig) {
            const cfg = Object.assign({}, CONFIG, customConfig || {});
            console.log('%c[DrawnApartSDK] 开始采集...', 'color: #6e45e2; font-weight: bold;');
            console.log('配置:', { numOfVertices: cfg.numOfVertices, rounds: cfg.rounds, timeout: cfg.timeout });

            return new Promise((resolve) => {
                if (typeof Worker === 'undefined' || typeof OffscreenCanvas === 'undefined') {
                    console.warn('[DrawnApartSDK] 当前浏览器不支持 Worker 或 OffscreenCanvas');
                    resolve({ success: false, error: 'Not supported', trace: null, method: 'offscreen' });
                    return;
                }

                const blob = new Blob([buildWorkerCode(cfg)], { type: 'text/javascript' });
                const worker = new Worker(window.URL.createObjectURL(blob));
                let finished = false;

                worker.onmessage = function(msg) {
                    finished = true;
                    worker.terminate();
                    console.log('[DrawnApartSDK] Worker 返回结果:', msg.data);
                    resolve(Object.assign({ method: 'offscreen' }, msg.data));
                };

                setTimeout(function() {
                    if (!finished) {
                        worker.terminate();
                        console.warn('[DrawnApartSDK] 采集超时');
                        resolve({ success: false, error: 'Timeout', trace: null, method: 'offscreen' });
                    }
                }, cfg.timeout);

                worker.postMessage('start');
            });
        },

        send: function(data, endpoint) {
            const url = endpoint || CONFIG.endpoint;
            const payload = Object.assign({
                url: window.location.href,
                referrer: document.referrer,
                userAgent: navigator.userAgent,
                timestamp: new Date().toISOString()
            }, data);

            console.log('%c[DrawnApartSDK] 将要发送的数据:', 'color: #6e45e2; font-weight: bold; font-size: 14px;');
            console.log('Endpoint:', url);
            console.log('Payload:', JSON.parse(JSON.stringify(payload)));
            console.log('Payload (JSON):', JSON.stringify(payload, null, 2));

            const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
            if (navigator.sendBeacon) {
                navigator.sendBeacon(url, blob);
            } else {
                fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                    keepalive: true
                }).catch(() => {});
            }
        }
    };

    const autoRun = document.currentScript && document.currentScript.dataset.auto !== 'false';

    if (autoRun) {
        if (document.readyState === 'complete') {
            setTimeout(runAutoCollect, 500);
        } else {
            window.addEventListener('load', function() {
                setTimeout(runAutoCollect, 500);
            });
        }
    }

    function runAutoCollect() {
        console.log('%c[DrawnApartSDK] 页面加载完成，500ms 后自动启动采集...', 'color: #6e45e2;');
        window.DrawnApartSDK.collect().then(function(result) {
            console.log('%c[DrawnApartSDK] 采集完成，准备发送/打印数据...', 'color: #6e45e2; font-weight: bold;');
            if (CONFIG.sendOnComplete) {
                window.DrawnApartSDK.send(result);
            }
            window.dispatchEvent(new CustomEvent('drawnapart:ready', { detail: result }));
        });
    }
})();
