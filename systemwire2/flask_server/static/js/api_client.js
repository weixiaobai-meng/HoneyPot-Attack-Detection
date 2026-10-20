/* Bounded, explicit JSON handling. Never retry a POST automatically. */
(function (root) {
    'use strict';
    let analysisPending = false;
    async function readJson(response) {
        const status = response.status;
        const label = `HTTP ${status}`;
        if (status === 401 || status === 403 ||
            (response.redirected && /\/manage\/login(?:[/?#]|$)/.test(response.url))) {
            throw new Error(`${label}：登录已失效，请重新登录后再操作。`);
        }
        const body = await response.text();
        if (!body.trim()) {
            throw new Error(`${label}：服务器或代理返回空响应；不能确定任务是否执行，请先读取最新结果，不要连续重复提交。`);
        }
        let payload;
        try { payload = JSON.parse(body); }
        catch (_) {
            throw new Error(`${label}：响应不是完整 JSON（可能为网关错误或连接中断）；请检查网络及服务器日志。`);
        }
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) || typeof payload.code !== 'number') {
            throw new Error(`${label}：接口响应格式不正确。`);
        }
        if (!response.ok || payload.code !== 0) {
            throw new Error(`${label}：${payload.message || '请求失败，请稍后检查服务状态。'}`);
        }
        return payload;
    }
    async function requestJson(url, options = {}) {
        const isAnalysis = (options.method || 'GET').toUpperCase() === 'POST' &&
            /^\/api\/analysis\/live(?:\/(?:balanced|scenario))?$/.test(url);
        if (isAnalysis && analysisPending) throw new Error('已有分析请求正在等待响应，请勿重复提交。');
        if (isAnalysis) analysisPending = true;
        const { timeoutMs = 180000, ...fetchOptions } = options;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const response = await fetch(url, { ...fetchOptions, signal: controller.signal });
            return await readJson(response);
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('等待响应超时，服务端任务可能仍在执行；请稍后读取最新结果，不要重复提交。');
            }
            if (error instanceof TypeError) {
                throw new Error('网络连接失败，请确认服务器地址可达且已绕过本机代理；任务状态未知。');
            }
            throw error;
        } finally { clearTimeout(timer); if (isAnalysis) analysisPending = false; }
    }
    root.HoneypotApi = { readJson, requestJson };
    if (typeof module !== 'undefined') module.exports = root.HoneypotApi;
})(typeof window !== 'undefined' ? window : globalThis);
