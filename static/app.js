class Dashboard {
    constructor() {
        this.token = localStorage.getItem('token');
        this.auditLogs = [];
        this.jwtCountdownInterval = null;
        this.jwtExpireTime = null;
        this.interceptChart = null;
        this.tokenChart = null;
        this.init();
    }

    async init() {
        this.setupEventListeners();
        this.initCharts();
        this.updateCacheStatus();
        this.addAuditLog('仪表板初始化完成', 'info');

        if (this.token) {
            const isValid = await this.validateToken();
            if (isValid) {
                this.updateJwtStatus(true);
                this.startJwtCountdown();
                await this.loadUsers();
                await this.updateAttackStats();
            } else {
                this.logout();
            }
        } else {
            this.updateJwtStatus(false);
        }
    }

    initCharts() {
        const interceptCtx = document.getElementById('intercept-chart').getContext('2d');
        this.interceptChart = new Chart(interceptCtx, {
            type: 'doughnut',
            data: {
                labels: ['拦截', '正常'],
                datasets: [{
                    data: [0, 100],
                    backgroundColor: ['#ef4444', '#48bb78'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '70%',
                plugins: { legend: { display: false }, tooltip: { enabled: true } }
            }
        });

        const tokenCtx = document.getElementById('token-chart').getContext('2d');
        this.tokenChart = new Chart(tokenCtx, {
            type: 'doughnut',
            data: {
                labels: ['活跃', '空闲'],
                datasets: [{
                    data: [0, 1],
                    backgroundColor: ['#667eea', '#e0e0e0'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                cutout: '70%',
                plugins: { legend: { display: false }, tooltip: { enabled: true } }
            }
        });
    }

    setupEventListeners() {
        document.getElementById('encrypt-btn').addEventListener('click', async () => { await this.encryptData(); });
        document.getElementById('decrypt-btn').addEventListener('click', async () => { await this.decryptData(); });
        document.getElementById('load-users').addEventListener('click', async () => { await this.loadUsers(); });
        document.getElementById('simulate-replay').addEventListener('click', async () => { await this.simulateReplayAttack(); });
        document.getElementById('simulate-rate-limit').addEventListener('click', async () => { await this.simulateRateLimit(); });
        document.getElementById('simulate-csrf').addEventListener('click', async () => { await this.simulateCsrfAttack(); });
        document.getElementById('login-btn').addEventListener('click', () => { this.openLoginModal(); });
        document.querySelector('.close').addEventListener('click', () => { this.closeLoginModal(); });
        document.getElementById('login-form').addEventListener('submit', async (e) => { e.preventDefault(); await this.login(); });
        document.getElementById('register-btn').addEventListener('click', async () => { await this.register(); });
        window.addEventListener('click', (e) => {
            const modal = document.getElementById('login-modal');
            if (e.target === modal) { this.closeLoginModal(); }
        });
    }

    openLoginModal() { document.getElementById('login-modal').style.display = 'flex'; }
    closeLoginModal() { document.getElementById('login-modal').style.display = 'none'; }

    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    setCookie(name, value, days = 1) {
        const expires = new Date();
        expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
        document.cookie = `${name}=${value};path=/;expires=${expires.toUTCString()}`;
    }

    async validateToken() {
        if (!this.token) return false;
        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/users/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                }
            });
            return response.ok;
        } catch (error) { return false; }
    }

    async login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (!username || !password) { alert('请输入用户名和密码'); return; }

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                },
                credentials: 'include',
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                const data = await response.json();
                this.token = data.access_token;
                localStorage.setItem('token', this.token);

                if (data.csrf_token) {
                    this.setCookie('csrf_token', data.csrf_token, 1);
                    localStorage.setItem('csrf_token', data.csrf_token);
                }

                this.jwtExpireTime = Date.now() + 2 * 60 * 1000;
                localStorage.setItem('jwtExpireTime', this.jwtExpireTime.toString());
                this.updateJwtStatus(true);
                this.closeLoginModal();
                this.startJwtCountdown();
                await this.loadUsers();
                await this.updateAttackStats();
                this.addAuditLog('用户登录成功', 'success');
            } else {
                const error = await response.json();
                alert('登录失败: ' + (error.detail || '用户名或密码错误'));
                this.addAuditLog('登录失败: ' + (error.detail || '用户名或密码错误'), 'error');
            }
        } catch (error) {
            alert('登录失败: ' + error.message);
            this.addAuditLog('登录失败: ' + error.message, 'error');
        }
    }

    logout() {
        this.token = null;
        localStorage.removeItem('token');
        localStorage.removeItem('jwtExpireTime');
        localStorage.removeItem('csrf_token');
        document.cookie = 'csrf_token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
        if (this.jwtCountdownInterval) { clearInterval(this.jwtCountdownInterval); this.jwtCountdownInterval = null; }
        this.updateJwtStatus(false);
        this.addAuditLog('用户已登出', 'info');
    }

    disableOperations() {
        const btns = ['encrypt-btn', 'decrypt-btn', 'load-users', 'simulate-replay', 'simulate-rate-limit', 'simulate-csrf'];
        btns.forEach(id => document.getElementById(id).disabled = true);
    }

    enableOperations() {
        const btns = ['encrypt-btn', 'decrypt-btn', 'load-users', 'simulate-replay', 'simulate-rate-limit', 'simulate-csrf'];
        btns.forEach(id => document.getElementById(id).disabled = false);
    }

    async register() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (!username || !password) { alert('请输入用户名和密码'); return; }

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                },
                credentials: 'include',
                body: JSON.stringify({
                    username, password,
                    email: `${username}@example.com`,
                    full_name: username
                })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.csrf_token) {
                    this.setCookie('csrf_token', data.csrf_token, 1);
                    localStorage.setItem('csrf_token', data.csrf_token);
                }
                this.addAuditLog('用户注册成功: ' + username, 'success');
                alert('注册成功，请登录');
            } else {
                const error = await response.json();
                alert('注册失败: ' + (error.detail || '用户名已存在'));
                this.addAuditLog('注册失败: ' + (error.detail || '用户名已存在'), 'error');
            }
        } catch (error) {
            alert('注册失败: ' + error.message);
            this.addAuditLog('注册失败: ' + error.message, 'error');
        }
    }

    getCsrfToken() {
        return localStorage.getItem('csrf_token') || this.getCookie('csrf_token') || '';
    }

    handleAuthError(status) {
        if (status === 401) {
            this.addAuditLog('认证失败: 令牌无效或已过期', 'error');
            this.logout();
            alert('登录已过期，请重新登录');
            return true;
        }
        return false;
    }

    async encryptData() {
        const plaintext = document.getElementById('plaintext').value;
        const fieldType = document.getElementById('field-type').value;
        if (!plaintext) { alert('请输入明文数据'); return; }

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/users/encrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp,
                    'X-CSRF-Token': this.getCsrfToken()
                },
                credentials: 'include',
                body: JSON.stringify({ data: plaintext, field_type: fieldType })
            });

            if (response.ok) {
                const data = await response.json();
                document.getElementById('ciphertext').value = data.encrypted;
                document.getElementById('masked-text').value = data.masked;
                this.addAuditLog(`加密成功 [${fieldType}]: ${plaintext} -> ${data.masked}`, 'success');
                await this.loadUsers();
                await this.updateAttackStats();
            } else if (this.handleAuthError(response.status)) {
                // 已处理认证错误
            } else {
                const error = await response.json();
                alert('加密失败: ' + (error.detail || '未知错误'));
                this.addAuditLog('加密失败: ' + (error.detail || '未知错误'), 'error');
            }
        } catch (error) {
            alert('加密失败: ' + error.message);
            this.addAuditLog('加密失败: ' + error.message, 'error');
        }
    }

    async decryptData() {
        const ciphertext = document.getElementById('ciphertext').value;
        if (!ciphertext) { alert('请输入密文数据'); return; }

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/users/decrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp,
                    'X-CSRF-Token': this.getCsrfToken()
                },
                credentials: 'include',
                body: JSON.stringify({ encrypted: ciphertext })
            });

            if (response.ok) {
                const data = await response.json();
                document.getElementById('plaintext').value = data.decrypted;
                this.addAuditLog('解密成功: ' + data.decrypted, 'success');
            } else if (this.handleAuthError(response.status)) {
                // 已处理认证错误
            } else {
                const error = await response.json();
                alert('解密失败: ' + (error.detail || '未知错误'));
                this.addAuditLog('解密失败: ' + (error.detail || '未知错误'), 'error');
            }
        } catch (error) {
            alert('解密失败: ' + error.message);
            this.addAuditLog('解密失败: ' + error.message, 'error');
        }
    }

    async loadUsers() {
        const container = document.getElementById('users-container');
        container.innerHTML = '<p>加载中...</p>';

        if (!this.token) {
            container.innerHTML = '<p style="color: #f6ad55;">请先登录</p>';
            return;
        }

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/users/me/masked`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                }
            });

            if (response.ok) {
                const user = await response.json();
                container.innerHTML = '';
                const userCard = document.createElement('div');
                userCard.className = 'user-card';
                userCard.innerHTML = `
                    <h4>${user.username}</h4>
                    <p>邮箱: ${user.email}</p>
                    <p>姓名: ${user.full_name}</p>
                    <p class="sensitive-field">手机: ${user.phone || '未设置'}</p>
                    <p class="sensitive-field">身份证: ${user.id_card || '未设置'}</p>
                    <p class="sensitive-field">银行卡: ${user.bank_card || '未设置'}</p>
                `;
                container.appendChild(userCard);
                this.addAuditLog('用户数据已更新', 'info');
            } else if (response.status === 401) {
                container.innerHTML = '<p style="color: #ef4444;">登录已过期，请重新登录</p>';
                this.handleAuthError(401);
            } else {
                container.innerHTML = '<p style="color: #f6ad55;">加载失败</p>';
                this.addAuditLog('加载用户数据失败', 'error');
            }
        } catch (error) {
            container.innerHTML = '<p style="color: #ef4444;">加载失败: ' + error.message + '</p>';
            this.addAuditLog('加载用户数据失败: ' + error.message, 'error');
        }
    }

    async simulateReplayAttack() {
        const resultBox = document.getElementById('replay-result');
        resultBox.innerHTML = '<p>准备模拟重放攻击...</p>';

        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();

            const firstResponse = await fetch(`${window.API_BASE}/api/users/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                }
            });

            if (firstResponse.ok) { resultBox.innerHTML += '<p style="color: #48bb78;">第一次请求成功</p>'; }

            await new Promise(resolve => setTimeout(resolve, 500));

            resultBox.innerHTML += '<p>尝试重放相同的nonce...</p>';
            const secondResponse = await fetch(`${window.API_BASE}/api/users/me`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce,
                    'X-Timestamp': timestamp
                }
            });

            if (secondResponse.status === 409) {
                resultBox.innerHTML += '<p style="color: #ef4444;">重放攻击被拦截！系统检测到重复的Nonce</p>';
                this.addAuditLog('重放攻击被拦截', 'warning');
            } else {
                resultBox.innerHTML += '<p style="color: #f6ad55;">未检测到重放攻击</p>';
            }
            await this.updateAttackStats();
        } catch (error) {
            resultBox.innerHTML += '<p style="color: #ef4444;">错误: ' + error.message + '</p>';
            this.addAuditLog('重放攻击模拟失败: ' + error.message, 'error');
        }
    }

    async simulateRateLimit() {
        const resultBox = document.getElementById('rate-limit-result');
        resultBox.innerHTML = '<p>开始发送大量请求（测试限流）...</p><div id="rate-limit-progress-bar" style="width: 0%; height: 10px; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); transition: width 0.3s;"></div>';

        let blockedCount = 0;
        const totalRequests = 20;

        for (let i = 0; i < totalRequests; i++) {
            try {
                const nonce = crypto.randomUUID();
                const timestamp = Date.now().toString();
                const response = await fetch(`${window.API_BASE}/api/users/me`, {
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'X-Nonce': nonce,
                        'X-Timestamp': timestamp
                    }
                });

                if (response.status === 429) { blockedCount++; }

                const progress = ((i + 1) / totalRequests) * 100;
                const progressBar = document.getElementById('rate-limit-progress-bar');
                if (progressBar) { progressBar.style.width = progress + '%'; }

                document.getElementById('rate-limit-count').textContent = `${i + 1}/${totalRequests}`;
            } catch (error) { console.error('Rate limit test error:', error); }
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        resultBox.innerHTML = `<p>测试完成: ${blockedCount}次请求被限流拦截</p>`;
        if (blockedCount > 0) {
            resultBox.innerHTML += '<p style="color: #ef4444;">限流防护生效！</p>';
            this.addAuditLog(`限流测试: ${blockedCount}次被拦截`, 'warning');
        } else {
            resultBox.innerHTML += '<p style="color: #f6ad55;">未触发限流</p>';
            this.addAuditLog('限流测试: 未触发限流', 'info');
        }
        await this.updateAttackStats();
    }

    async simulateCsrfAttack() {
        const resultBox = document.getElementById('csrf-result');
        resultBox.innerHTML = '<p>开始CSRF攻击模拟...</p><p>测试1: 无CSRF Token的请求...</p>';

        try {
            const nonce1 = crypto.randomUUID();
            const timestamp1 = Date.now().toString();
            const noTokenResponse = await fetch(`${window.API_BASE}/api/auth/change-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': nonce1,
                    'X-Timestamp': timestamp1
                },
                body: JSON.stringify({
                    current_password: 'test',
                    new_password: 'test1234'
                })
            });

            if (noTokenResponse.status === 403) {
                resultBox.innerHTML += '<p style="color: #48bb78;">✅ 无Token请求被正确拦截（CSRF防护生效）</p>';
                this.addAuditLog('CSRF攻击(无Token)被拦截', 'warning');
            } else {
                resultBox.innerHTML += '<p style="color: #f6ad55;">⚠️ 请求未被拦截</p>';
            }

            resultBox.innerHTML += '<p>测试2: 有CSRF Token但Cookie为空...</p>';
            const wrongTokenResponse = await fetch(`${window.API_BASE}/api/auth/change-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`,
                    'X-Nonce': crypto.randomUUID(),
                    'X-Timestamp': Date.now().toString(),
                    'X-CSRF-Token': 'wrong-token'
                },
                body: JSON.stringify({
                    current_password: 'test',
                    new_password: 'test1234'
                })
            });

            if (wrongTokenResponse.status === 403) {
                resultBox.innerHTML += '<p style="color: #48bb78;">✅ 错误Token请求被正确拦截</p>';
                this.addAuditLog('CSRF攻击(错误Token)被拦截', 'warning');
            } else {
                resultBox.innerHTML += '<p style="color: #f6ad55;">⚠️ 错误Token请求未被拦截</p>';
            }

            await this.updateAttackStats();
        } catch (error) {
            resultBox.innerHTML += '<p style="color: #ef4444;">错误: ' + error.message + '</p>';
            this.addAuditLog('CSRF模拟失败: ' + error.message, 'error');
        }
    }

    updateJwtStatus(isLoggedIn) {
        const statusElement = document.getElementById('jwt-status');
        if (isLoggedIn) {
            statusElement.textContent = '已登录';
            statusElement.style.color = '#48bb78';
            document.getElementById('login-btn').textContent = '已登录';
            this.enableOperations();
            if (this.tokenChart) { this.tokenChart.data.datasets[0].data = [1, 0]; this.tokenChart.update(); }
        } else {
            statusElement.textContent = '未登录';
            statusElement.style.color = '#ef4444';
            document.getElementById('login-btn').textContent = '登录/注册';
            document.getElementById('jwt-countdown').textContent = '02:00';
            document.getElementById('jwt-countdown').style.color = '#667eea';
            this.disableOperations();
            if (this.tokenChart) { this.tokenChart.data.datasets[0].data = [0, 1]; this.tokenChart.update(); }
        }
    }

    updateCacheStatus() {
        const statusElement = document.getElementById('cache-status');
        statusElement.textContent = '正常';
        statusElement.style.color = '#48bb78';
    }

    startJwtCountdown() {
        const countdownElement = document.getElementById('jwt-countdown');
        if (this.jwtCountdownInterval) { clearInterval(this.jwtCountdownInterval); }

        if (!this.jwtExpireTime) {
            const storedExpire = localStorage.getItem('jwtExpireTime');
            if (storedExpire) { this.jwtExpireTime = parseInt(storedExpire); }
            else { this.jwtExpireTime = Date.now() + 2 * 60 * 1000; localStorage.setItem('jwtExpireTime', this.jwtExpireTime.toString()); }
        }

        const updateCountdown = () => {
            const now = Date.now();
            const remaining = Math.max(0, this.jwtExpireTime - now);
            const totalSeconds = Math.floor(remaining / 1000);
            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;
            countdownElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            countdownElement.style.color = totalSeconds <= 30 ? '#f6ad55' : '#48bb78';
            if (totalSeconds <= 0) {
                clearInterval(this.jwtCountdownInterval);
                this.jwtCountdownInterval = null;
                countdownElement.textContent = '00:00';
                countdownElement.style.color = '#ef4444';
                this.addAuditLog('JWT令牌已过期，用户被踢下线', 'warning');
                this.logout();
                alert('登录已过期，请重新登录');
            }
        };

        updateCountdown();
        this.jwtCountdownInterval = setInterval(updateCountdown, 1000);
    }

    async updateAttackStats() {
        const countElement = document.getElementById('attack-count');
        try {
            const nonce = crypto.randomUUID();
            const timestamp = Date.now().toString();
            const response = await fetch(`${window.API_BASE}/api/stats/attacks`, {
                headers: { 'X-Nonce': nonce, 'X-Timestamp': timestamp }
            });
            if (response.ok) {
                const data = await response.json();
                const total = data.total_blocked || 0;
                countElement.textContent = total;
                if (this.interceptChart) {
                    this.interceptChart.data.datasets[0].data = [total, Math.max(100 - total, 0)];
                    this.interceptChart.update();
                }
            }
        } catch (error) { console.error('获取攻击统计数据失败:', error); }
    }

    addAuditLog(message, level = 'info') {
        this.auditLogs.unshift({ message, level, time: new Date().toLocaleTimeString() });
        this.updateAuditLogs();
    }

    updateAuditLogs() {
        const container = document.getElementById('logs-container');
        if (!container) return;
        container.innerHTML = '';
        const logsToShow = this.auditLogs.slice(0, 20);
        logsToShow.forEach(log => {
            const logElement = document.createElement('div');
            logElement.className = 'log-entry';
            let levelColor = '#e0e0e0';
            if (log.level === 'success') levelColor = '#48bb78';
            else if (log.level === 'error') levelColor = '#ef4444';
            else if (log.level === 'warning') levelColor = '#f6ad55';
            else if (log.level === 'info') levelColor = '#63b3ed';
            logElement.innerHTML = `<span class="log-time" style="color: #a0a0a0;">${log.time}</span><span class="log-level" style="color: ${levelColor};">[${log.level.toUpperCase()}]</span><span class="log-message" style="color: #e0e0e0;">${log.message}</span>`;
            container.appendChild(logElement);
        });
        if (logsToShow.length === 0) { container.innerHTML = '<p style="color: #a0a0a0;">暂无审计日志</p>'; }
    }
}

document.addEventListener('DOMContentLoaded', () => { new Dashboard(); });
