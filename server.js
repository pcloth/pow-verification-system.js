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
        // 创建RSA密钥对象并设置兼容JSEncrypt的配置
        const key = new NodeRSA();
        key.importKey(PRIVATE_KEY, 'private');
        key.setOptions({
            encryptionScheme: 'pkcs1',  // 使用PKCS#1 v1.5填充
            environment: 'browser',     // 设置为浏览器环境兼容模式
            signingScheme: 'pkcs1-sha256' // 签名方案与JSEncrypt一致
        });
        
        // 解密数据
        console.log('开始解密数据...');
        const decrypted = key.decrypt(encryptedData, 'utf8');
        console.log('数据解密成功:', decrypted);
        
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
        // 处理本地IP的不同表示形式：127.0.0.1和::1
        const isLocalDecryptedIp = decryptedIp === '127.0.0.1' || decryptedIp === 'localhost';
        const isLocalServerIp = ipAddress === '127.0.0.1' || ipAddress === '::1' || ipAddress === 'localhost';
        
        console.log('解密的IP:', decryptedIp, '服务器检测到的IP:', ipAddress);
        
        if (decryptedIp !== ipAddress && !(isLocalDecryptedIp && isLocalServerIp)) {
            console.log('IP地址不匹配:', decryptedIp, ipAddress);
            return { valid: false, reason: `IP地址不匹配: 预期 ${decryptedIp}, 实际 ${ipAddress}` };
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
        // 提供更详细的错误信息
        console.error('错误类型:', e.constructor.name);
        console.error('错误堆栈:', e.stack);
        console.error('加密数据长度:', encryptedData ? encryptedData.length : 'undefined');
        
        return { valid: false, reason: '验证错误: ' + e.message };
    }
}

// 验证接口
app.post('/verify', (req, res) => {
    const { encrypted, next, stats } = req.body;
    
// 获取客户端IP，处理各种格式的情况
let clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
console.log('原始客户端IP:', clientIp);

// 如果是IPv6格式的本地回环地址（::1），转换为IPv4格式（127.0.0.1）
if (clientIp === '::1') {
    clientIp = '127.0.0.1';
}
// 处理 IPv4-mapped IPv6 地址格式（::ffff:x.x.x.x）
else if (clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7); // 去掉 ::ffff: 前缀
}
// 如果IP地址包含端口号，去掉端口号部分
if (clientIp.includes(':')) {
    const lastColonIndex = clientIp.lastIndexOf(':');
    // 确保不是IPv6地址的一部分（IPv6地址中有多个冒号）
    if (clientIp.indexOf(':') === lastColonIndex) {
        clientIp = clientIp.substring(0, lastColonIndex);
    }
}    console.log('收到验证请求，客户端IP:', clientIp);
    
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

// 测试密钥对
function testKeyPair() {
    try {
        console.log('测试RSA密钥对...');
        
        // 从私钥中提取公钥
        const key = new NodeRSA();
        key.importKey(PRIVATE_KEY, 'private');
        key.setOptions({
            encryptionScheme: 'pkcs1',
            environment: 'browser',
            signingScheme: 'pkcs1-sha256'
        });
        
        // 测试文本
        const testMessage = 'Hello, World!';
        
        // 使用公钥加密
        const encrypted = key.encrypt(testMessage, 'base64');
        console.log('加密测试消息:', encrypted);
        
        // 使用私钥解密
        const decrypted = key.decrypt(encrypted, 'utf8');
        console.log('解密测试消息:', decrypted);
        
        if (testMessage === decrypted) {
            console.log('✅ 密钥对测试成功');
        } else {
            console.error('❌ 密钥对测试失败: 解密结果与原始消息不匹配');
        }
    } catch (e) {
        console.error('❌ 密钥对测试失败:', e);
    }
}

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在 http://localhost:${port}`);
    
    // 测试密钥对
    testKeyPair();
});