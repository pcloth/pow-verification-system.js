const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const NodeRSA = require('node-rsa');
const app = express();
const port = 3000;

// 中间件设置
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// 服务器端私钥（与前端公钥对应）
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCFVqa0S89jMU2TtFwJoA7ZsOXmT9d/5+IbqxB2gydx8HVkrtA7
JfPElnnU9gGwxiTreWjkDTx8sYEC4K0wGHkzowh1fOdv747n3pNyun5D4BgiLwV+
YT6opRs9D/MNjuXSLGJJ5h8BkHJjBVqykK8LyREvMXXiB62VWC88fKwMUQIDAQAB
AoGAFaGhGc7SrjzpYPT5mXYl8psIMPzy8QUlYWe3HALa+1kPMm5Jyc62ZUYkLbBb
RdpfUvQ3WAftsCz7yQO6FPtjbgdf/9iOienYgAL2kxn6D3yjzMGxQ2zIzPkYA89/
cKgZfv6NC2of2wOaiIzgRRgxkbDOIVAFlZoEaBIeaFHT66ECQQDryQIRzzbZ0zkm
9enisu6/QUG5pIPdNicNk3wbcmCempkAgML9YqhgOihm11rEWClgP8HHAtnQj3zy
TL/ZYlVLAkEAkMUm7rJ0+3pWaUAoUvNdDqdDuKcp8uJS7kjW7RrFzGnfaBNeq5g0
HvE+GcYjAevufNsB+ZjYEYHTR98nTIEPUwJBAMee5YaodZrTblai6kIJFYKMwBVo
yE83sraWwAMIwe5lmtXHLc6SgVT+yAfRmcITlewr7mYL7tbZNIJ7Ig3sZ6MCQBf3
q+Rkwx1HObsfFg31oHhmlL2jXzyI37X3dS23+vtGo+f1HP1Hq4lb4y4dMXqF9uvQ
zljmRw9O8Q27EiSGUWUCQQCfw5ZgH0yA0wsugeJoXer+JFUAztwdJydN6XHvpTjB
1oBaJfM/CewngIvz8mYwoYV29xKRfmi3teuBgHo1L7yG
-----END RSA PRIVATE KEY-----`;

// 预设的校验哈希值（在实际应用中应该动态生成）
const PREVIOUS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// 验证工作量证明的函数
function verifyProofOfWork(encryptedData, ipAddress, difficulty) {
    try {
        // 创建RSA密钥对象
        const key = new NodeRSA();
        key.importKey(PRIVATE_KEY, 'private');
        
        // 解密数据
        const decrypted = key.decrypt(encryptedData, 'utf8');
        
        // 解析解密后的数据
        const parts = decrypted.split(',');
        if (parts.length !== 4) {
            return { valid: false, reason: '数据格式无效' };
        }
        
        const decryptedIp = parts[0];
        const hash = parts[1];
        const timestamp = parts[2];
        const nonce = parseInt(parts[3], 10);
        
        // 验证IP地址
        if (decryptedIp !== ipAddress) {
            return { valid: false, reason: 'IP地址不匹配' };
        }
        
        // 验证哈希前缀是否符合难度要求
        const prefix = '0'.repeat(difficulty);
        if (hash.substring(0, difficulty) !== prefix) {
            return { valid: false, reason: '哈希不符合难度要求' };
        }
        
        // 验证哈希是否有效
        const calculatedHash = crypto.createHash('sha256')
            .update(ipAddress + PREVIOUS_HASH + nonce)
            .digest('hex');
            
        if (calculatedHash !== hash) {
            return { valid: false, reason: '哈希验证失败' };
        }
        
        // 验证时间戳是否在合理范围内
        const currentTime = new Date().getTime();
        const timeDiff = currentTime - parseInt(timestamp, 10);
        if (timeDiff > 3600000) { // 1小时过期
            return { valid: false, reason: '工作量证明已过期' };
        }
        
        return {
            valid: true,
            ip: decryptedIp,
            hash: hash,
            timestamp: timestamp,
            nonce: nonce
        };
    } catch (e) {
        console.error('验证错误:', e);
        return { valid: false, reason: '验证错误: ' + e.message };
    }
}

// 验证接口
app.post('/verify', (req, res) => {
    const { encrypted, next, stats } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
    
    // 解析统计数据（如有）
    let statsData = {};
    try {
        if (stats) {
            statsData = JSON.parse(stats);
        }
    } catch (e) {
        console.error('解析统计数据失败:', e);
    }
    
    // 验证开始时间
    const verifyStartTime = Date.now();
    
    // 验证工作量证明
    const result = verifyProofOfWork(encrypted, clientIp, statsData.difficulty || 4);
    
    // 验证耗时
    const verifyTime = Date.now() - verifyStartTime;
    
    // 记录验证结果和性能数据
    console.log('验证结果:', result);
    console.log('验证耗时:', verifyTime, 'ms');
    console.log('客户端计算耗时:', statsData.totalTime, 'ms');
    console.log('难度:', statsData.difficulty);
    console.log('客户端尝试次数:', statsData.nonce);
    
    if (result.valid) {
        // 验证成功，重定向到next指定的URL
        const redirectUrl = next || '/';
        res.redirect(redirectUrl);
    } else {
        // 验证失败，返回错误页面
        res.status(403).send(`
            <html>
                <head>
                    <title>验证失败</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            background-color: #f5f7fa;
                        }
                        .error-container {
                            padding: 30px;
                            border-radius: 8px;
                            background-color: white;
                            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                            text-align: center;
                            max-width: 500px;
                        }
                        h1 { color: #e74c3c; }
                        p { color: #555; line-height: 1.6; }
                        button {
                            background-color: #3498db;
                            color: white;
                            border: none;
                            padding: 10px 20px;
                            border-radius: 4px;
                            cursor: pointer;
                            margin-top: 20px;
                        }
                    </style>
                </head>
                <body>
                    <div class="error-container">
                        <h1>验证失败</h1>
                        <p>原因: ${result.reason}</p>
                        <p>您的请求未通过工作量证明验证，请重试。</p>
                        <button onclick="window.location.href='/?next=${encodeURIComponent(next || '/')}'">重新验证</button>
                    </div>
                </body>
            </html>
        `);
    }
});

// 首页路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在 http://localhost:${port}`);
});