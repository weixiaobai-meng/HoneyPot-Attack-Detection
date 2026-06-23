function initializeBotDetection(callbacks = {}) {
    const runtime = window.__rtCfg__ || {};

    class BotDetectionClient {
        constructor(callbacks) {
            this.sessionToken = window.sessionToken;
            this.mouseTrack = [];
            this.clickTimes = [];
            this.keypressTimes = [];
            this.scrollTimes = [];
            this.isBotDetected = false;
            this.currentScore = 0;
            this.lastMouseEvent = null;
            this.scrollTimeout = null;

            this.callbacks = callbacks;

            this.initEventListeners();
        }

        initEventListeners() {
            const trackMouse = (e) => {
                const now = Date.now();

                if (this.lastMouseEvent) {
                    const dx = e.clientX - this.lastMouseEvent.x;
                    const dy = e.clientY - this.lastMouseEvent.y;
                    const dt = now - this.lastMouseEvent.time;

                    if (dt > 0) {
                        const distance = Math.sqrt(dx * dx + dy * dy);
                        const speed = distance / dt;

                        this.mouseTrack.push([
                            e.clientX,
                            e.clientY,
                            now,
                            speed
                        ]);
                    }
                }

                if (this.mouseTrack.length > 500) {
                    this.mouseTrack = this.mouseTrack.slice(-500);
                }

                this.lastMouseEvent = {
                    x: e.clientX,
                    y: e.clientY,
                    time: now
                };
            };

            document.addEventListener('mousemove', (e) => {
                if (!this.isBotDetected) {
                    window.requestAnimationFrame(() => trackMouse(e));
                }
            });

            document.addEventListener('click', () => {
                if (this.isBotDetected) return;
                this.clickTimes.push(Date.now());
                if (this.clickTimes.length > 100) {
                    this.clickTimes = this.clickTimes.slice(-50);
                }
            });

            document.addEventListener('keydown', (e) => {
                if (this.isBotDetected || e.ctrlKey || e.altKey || e.metaKey) return;
                this.keypressTimes.push(Date.now());
                if (this.keypressTimes.length > 200) {
                    this.keypressTimes = this.keypressTimes.slice(-100);
                }
            });

            document.addEventListener('scroll', () => {
                if (this.isBotDetected) return;
                clearTimeout(this.scrollTimeout);
                this.scrollTimeout = setTimeout(() => {
                    this.scrollTimes.push(Date.now());
                    if (this.scrollTimes.length > 50) {
                        this.scrollTimes = this.scrollTimes.slice(-25);
                    }
                }, 100);
            });

            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    this.pauseDetection();
                }
            });
        }

        calculateClickIntervals() {
            if (this.clickTimes.length < 2) return [];
            const intervals = [];
            for (let i = 1; i < this.clickTimes.length; i++) {
                intervals.push(this.clickTimes[i] - this.clickTimes[i - 1]);
            }
            return intervals;
        }

        async submitBehaviorData() {
            if (this.isBotDetected) return;

            const data = {
                sessionToken: this.sessionToken,
                mouseTrack: this.mouseTrack.map(point => [point[0], point[1]]),
                mouseMeta: {
                    timestamps: this.mouseTrack.map(point => point[2]),
                    speeds: this.mouseTrack.map(point => point[3])
                },
                clickIntervals: this.calculateClickIntervals(),
                userAgent: navigator.userAgent,
                timestamp: Date.now(),
                viewport: {
                    width: window.innerWidth,
                    height: window.innerHeight
                }
            };

            try {
                const response = await fetch(runtime.botUrl ? runtime.botUrl() : "./cdn/security/verify", {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });

                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

                const result = await response.json();
                this.handleBotCheckResponse(result);

            } catch (error) {
            }
        }

        handleBotCheckResponse(result) {
            this.currentScore = result.score || 0;

            if (result.isBot) {
                this.isBotDetected = true;
                this.stopDetection();
                this.limitBotActions();
            }

            if (this.callbacks.onDetection) {
                this.callbacks.onDetection({
                    isBot: this.isBotDetected,
                    score: this.currentScore,
                    sessionToken: this.sessionToken,
                    debugInfo: result.debugInfo
                });
            }
        }

        updateUI() {
            if (this.callbacks.onUpdate) {
                this.callbacks.onUpdate({
                    sessionToken: this.sessionToken,
                    currentScore: this.currentScore
                });
            }
        }

        limitBotActions() {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', (e) => {
                    if (this.isBotDetected) {
                        e.preventDefault();
                    }
                });
            });
        }

        pauseDetection() {
        }

        stopDetection() {
            this.mouseTrack = [];
            this.clickTimes = [];
            this.keypressTimes = [];
            this.scrollTimes = [];
        }

        manualCheck() {
            this.submitBehaviorData();
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        window.botDetector = new BotDetectionClient(callbacks);

        const delay = 3000 + Math.floor(Math.random() * 4000);
        setTimeout(() => {
            window.botDetector.submitBehaviorData();
        }, delay);
    });

    window.addEventListener('beforeunload', () => {
        if (window.botDetector) {
            window.botDetector.stopDetection();
        }
    });
}

initializeBotDetection();
