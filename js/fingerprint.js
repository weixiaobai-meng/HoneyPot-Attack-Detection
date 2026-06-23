function initializeFingerprintDetection() {
    const ClientJS = window.ClientJS;
    const client = new ClientJS();
    const runtime = window.__rtCfg__ || {};

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

        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'Unknown';
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'Unknown';
            return { vendor, renderer };
        }

        return {
            vendor: gl.getParameter(gl.VENDOR) || 'Unknown',
            renderer: gl.getParameter(gl.RENDERER) || 'Unknown'
        };
    }

    async function runCheck() {
        const [cpuCores, gpuInfo] = await Promise.all([
            getCpuCores(),
            getDetailedGPUInfo(),
        ]);
        const pageTarget = runtime.pageTarget
            ? runtime.pageTarget()
            : (window.location.href || window.location.host || "unknown");

        const fingerprintData = {
            path: pageTarget,
            fingerprint: client.getFingerprint(),
            userAgent: client.getUserAgent(),
            browser: client.getBrowser(),
            browserVersion: client.getBrowserVersion(),
            os: client.getOS(),
            osVersion: client.getOSVersion(),
            device: client.getDevice(),
            cpu: client.getCPU(),
            cpuCores: cpuCores,
            gpuInfo: gpuInfo,
            isMobile: client.isMobile(),
            screenPrint: client.getScreenPrint(),
            plugins: client.getPlugins(),
            fonts: client.getFonts(),
            isLocalStorage: client.isLocalStorage(),
            sessionStorage: client.isSessionStorage(),
            isCookie: client.isCookie(),
            timeZone: client.getTimeZone(),
            language: client.getLanguage(),
            canvas: client.getCanvasPrint(),
            sessionToken: window.sessionToken
        };

        var xhr = new XMLHttpRequest();
        var url = runtime.buildHttpUrl
            ? runtime.buildHttpUrl("cdn/analytics")
            : (runtime.infoUrl ? runtime.infoUrl() : "./cdn/analytics");
        xhr.open("POST", url, true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(JSON.stringify(fingerprintData));
    }

    document.addEventListener('DOMContentLoaded', () => {
        runCheck();
    });

    window.addEventListener('beforeunload', () => {
    });
}

initializeFingerprintDetection();
