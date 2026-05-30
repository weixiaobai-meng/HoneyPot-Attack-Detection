(function() {
    // 如果已经存在，不重复生成
    if (window.sessionToken) return;

    function generateSessionToken() {
        const randomPart = window.crypto
            ? window.crypto.getRandomValues(new Uint32Array(1))[0].toString(36)
            : Math.random().toString(36).substring(2);
        return `sess-${randomPart}-${Date.now()}`;
    }

    // 生成并赋值给全局变量
    window.sessionToken = generateSessionToken();

    console.log("Session Token generated:", window.sessionToken);
})();
