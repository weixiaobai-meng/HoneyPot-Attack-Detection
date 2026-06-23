(function() {
    function buildPageTarget() {
        try {
            var href = window.location.href || "";
            if (href && href !== "about:blank") {
                return href.split("#")[0];
            }
        } catch (error) {}

        try {
            if (window.location.host) {
                return window.location.host;
            }
            if (window.location.pathname) {
                return window.location.pathname;
            }
        } catch (error) {}

        return "unknown";
    }

    if (!window.__rtCfg__) {
        const infoUrl = "./cdn/analytics";
        const ipsUrl = "./cdn/analytics/geo";
        const botUrl = "./cdn/security/verify";
        const wsUrl = "./socket";

        window.__rtCfg__ = {
            pageTarget: buildPageTarget,
            infoUrl: function() { return infoUrl; },
            ipsUrl: function() { return ipsUrl; },
            botUrl: function() { return botUrl; },
            wsUrl: function() { return wsUrl; }
        };
    }

    if (window.sessionToken) return;

    function generateSessionToken() {
        const randomPart = window.crypto
            ? window.crypto.getRandomValues(new Uint32Array(1))[0].toString(36)
            : Math.random().toString(36).substring(2);
        return `sess-${randomPart}-${Date.now()}`;
    }

    window.sessionToken = generateSessionToken();
})();
