function initializeFingerprintDetection() {
    const ClientJS = window.ClientJS;
    const client = new ClientJS();

    async function getCpuCores() {
        const cpuCores = navigator.hardwareConcurrency || "Unknown";
        return cpuCores;
    }

    async function getDetailedGPUInfo() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

        if (!gl) {
            return { vendor: 'WebGL not supported', renderer: 'WebGL not supported' };
        }

        // 尝试获取更详细的 GPU 信息
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'Unknown';
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'Unknown';
            return { vendor, renderer };
        } else {
            // 如果无法获取扩展信息，返回默认值
            return {
                vendor: gl.getParameter(gl.VENDOR) || 'Unknown',
                renderer: gl.getParameter(gl.RENDERER) || 'Unknown'
            };
        }
    }

    async function runCheck() {
        const [cpuCores, gpuInfo] = await Promise.all([
            getCpuCores(),
            getDetailedGPUInfo(),
        ]);

        const fingerprintData = {
            path: window.location.host,
            fingerprint: client.getFingerprint(),
            userAgent: client.getUserAgent(),
            browser: client.getBrowser(), //浏览器
            browserVersion: client.getBrowserVersion(), //浏览器版本
            os: client.getOS(), //操作系统
            osVersion: client.getOSVersion(), //操作系统版本号
            device: client.getDevice(),
            cpu: client.getCPU(), //cpu架构
            cpuCores: cpuCores, //逻辑 CPU 核心数
            gpuInfo: gpuInfo, //GPU信息
            isMobile: client.isMobile(), //设备类型
            screenPrint: client.getScreenPrint(), //屏幕的相关信息，如分辨率、颜色深度等
            plugins: client.getPlugins(), //插件
            fonts: client.getFonts(), //字体
            isLocalStorage: client.isLocalStorage(),
            sessionStorage: client.isSessionStorage(),
            isCookie: client.isCookie(),
            timeZone: client.getTimeZone(), //时区
            language: client.getLanguage(), //语言
            canvas: client.getCanvasPrint(), //canvas指纹
            sessionToken: window.sessionToken
        };

        // 发送数据到服务器
        var xhr = new XMLHttpRequest();
        var url = "./info/"; 
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify(fingerprintData));

        console.log("Fingerprint data sent:", fingerprintData);
    }

    // 页面加载后调用
    document.addEventListener('DOMContentLoaded', () => {
        runCheck();
        console.log("Fingerprint detection initialized.");
    });

    // 页面卸载前清理
    window.addEventListener('beforeunload', () => {
        console.log('Stopping fingerprint detection');
    });
}


initializeFingerprintDetection();
