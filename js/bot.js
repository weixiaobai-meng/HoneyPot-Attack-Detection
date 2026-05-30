function initializeBotDetection(callbacks = {}) {
    class BotDetectionClient {
        constructor(callbacks) {
            // 使用更可靠的SessionToken生成方式
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
            // 使用requestAnimationFrame优化鼠标轨迹收集
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

                // 使用环形缓冲区限制轨迹长度
                if (this.mouseTrack.length > 500) {
                    this.mouseTrack = this.mouseTrack.slice(-500);
                }

                this.lastMouseEvent = {
                    x: e.clientX,
                    y: e.clientY,
                    time: now
                };
            };

            // 使用节流优化事件监听
            document.addEventListener('mousemove', (e) => {
                if (!this.isBotDetected) {
                    window.requestAnimationFrame(() => trackMouse(e));
                }
            });

            // 点击事件
            document.addEventListener('click', (e) => {
                if (this.isBotDetected) return;
                this.clickTimes.push(Date.now());
                if (this.clickTimes.length > 100) {
                    this.clickTimes = this.clickTimes.slice(-50);
                }
            });

            // 键盘事件
            document.addEventListener('keydown', (e) => {
                if (this.isBotDetected || e.ctrlKey || e.altKey || e.metaKey) return;
                this.keypressTimes.push(Date.now());
                if (this.keypressTimes.length > 200) {
                    this.keypressTimes = this.keypressTimes.slice(-100);
                }
            });

            // 滚动事件（防抖处理）
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

            // 页面可见性变化
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

            // 准备符合后端要求的数据格式
            const data = {
                sessionToken: this.sessionToken,
                mouseTrack: this.mouseTrack.map(point => [point[0], point[1]]), // 只传x,y坐标
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
                const response = await fetch('./bot-check', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Client-Version': '1.1'
                    },
                    body: JSON.stringify(data)
                });

                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

                const result = await response.json();
                this.handleBotCheckResponse(result);

            } catch (error) {
                console.error('Bot check submission failed:', error);
            }
        }

        handleBotCheckResponse(result) {
            console.log('Bot detection result:', result);

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
            // 不再直接更新页面内容
            if (this.callbacks.onUpdate) {
                this.callbacks.onUpdate({
                    sessionToken: this.sessionToken,
                    currentScore: this.currentScore
                });
            }
        }

        limitBotActions() {
            console.log('Limiting actions for detected bot');
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', (e) => {
                    if (this.isBotDetected) {
                        e.preventDefault();
                        alert('操作被限制：检测到自动化行为');
                    }
                });
            });
        }

        pauseDetection() {
            console.log('Pausing bot detection (page hidden)');
        }

        stopDetection() {
            console.log('Stopping bot detection');
            this.mouseTrack = [];
            this.clickTimes = [];
            this.keypressTimes = [];
            this.scrollTimes = [];
        }

        manualCheck() {
            this.submitBehaviorData();
        }
    }

    // 页面加载完成后初始化
    document.addEventListener('DOMContentLoaded', () => {
        // 初始化机器人检测
        window.botDetector = new BotDetectionClient(callbacks);

        // 页面加载后5秒发送一次数据
        setTimeout(() => {
            window.botDetector.submitBehaviorData();
        }, 5000);

        console.log('Bot detection initialized. Session:', window.botDetector.sessionToken);
    });


    // 页面卸载前清理
    window.addEventListener('beforeunload', () => {
        if (window.botDetector) {
            window.botDetector.stopDetection();
        }
    });
}

initializeBotDetection();