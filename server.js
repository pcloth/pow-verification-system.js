const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const app = express();
const port = 3000;

// 中间件设置
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser()); // 添加cookie解析中间件
// 自定义静态文件中间件，排除index.html，让路由处理它
app.use(express.static(path.join(__dirname, 'public'), {
    index: false  // 禁用自动提供index.html
}));

// 生成当天的previousHash
function generatePreviousHash(ipAddress) {
    // 获取当前日期，格式为YYYY-MM-DD
    const today = new Date().toISOString().split('T')[0];
    // 特殊字符串
    const specialString = 'adf!21*';
    // 组合IP地址、日期和特殊字符串
    const data = ipAddress + today + specialString;
    // 计算SHA-256哈希
    return crypto.createHash('sha256').update(data).digest('hex');
}

// 验证cookie的函数
function validateCookie(req, res) {
    try {
        // 获取x-hash cookie
        const cookieData = req.cookies['x-hash'];
        if (!cookieData) {
            return { valid: false, reason: 'Cookie不存在' };
        }

        // 解析cookie数据
        const data = JSON.parse(cookieData);
        const { hash, nonce, ip, timestamp } = data;

        // 检查时间戳是否过期（24小时有效期）
        const now = Date.now();
        if (now - timestamp > 24 * 60 * 60 * 1000) {
            return { valid: false, reason: 'Cookie已过期' };
        }

        // 获取当前客户端IP
        let clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
        
        // 处理IP格式
        if (clientIp === '::1') {
            clientIp = '127.0.0.1';
        } else if (clientIp.startsWith('::ffff:')) {
            clientIp = clientIp.substring(7);
        }
        if (clientIp.includes(':')) {
            const lastColonIndex = clientIp.lastIndexOf(':');
            if (clientIp.indexOf(':') === lastColonIndex) {
                clientIp = clientIp.substring(0, lastColonIndex);
            }
        }

        // 检查IP地址是否匹配（可选，取决于您的安全需求）
        if (ip !== clientIp) {
            console.log(`IP不匹配: Cookie IP=${ip}, 当前IP=${clientIp}`);
            // 本地开发时可能会有不同的IP，所以我们只记录而不拒绝
            // return { valid: false, reason: 'IP地址不匹配' };
        }

        // 验证工作量证明
        // 通常我们会用默认的难度4，但如果需要更严格的验证，可以从cookie中提取难度
        const result = verifyProofOfWork(ip, hash, parseInt(nonce, 10), 4);
        
        return result;
    } catch (e) {
        console.error('Cookie验证错误:', e);
        return { valid: false, reason: '验证错误: ' + e.message };
    }
}

// 验证工作量证明的函数
function verifyProofOfWork(clientIp, hash, nonce, difficulty) {
    try {
        // 生成previousHash
        const previousHash = generatePreviousHash(clientIp);
        
        console.log('验证参数:', {
            clientIp,
            previousHash,
            nonce,
            difficulty
        });
        
        // 验证哈希前缀是否符合难度要求
        const prefix = '0'.repeat(difficulty);
        if (hash.substring(0, difficulty) !== prefix) {
            return { valid: false, reason: '哈希不符合难度要求' };
        }
        
        // 验证哈希是否有效
        const calculatedHash = crypto.createHash('sha256')
            .update(clientIp + previousHash + nonce)
            .digest('hex');
            
        if (calculatedHash !== hash) {
            return { valid: false, reason: '哈希验证失败' };
        }
        
        return {
            valid: true,
            hash: hash,
            nonce: nonce
        };
    } catch (e) {
        console.error('验证错误:', e);
        // 提供更详细的错误信息
        console.error('错误类型:', e.constructor.name);
        console.error('错误堆栈:', e.stack);
        
        return { valid: false, reason: '验证错误: ' + e.message };
    }
}

// 验证接口
app.post('/verify', (req, res) => {
    const { hash, next, stats, nonce } = req.body;
    
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
    }
    console.log('收到验证请求，客户端IP:', clientIp);
    
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
    const result = verifyProofOfWork(clientIp, hash, parseInt(nonce, 10), statsData.difficulty || 4);
    
    // 验证耗时
    const verifyTime = Date.now() - verifyStartTime;
    
    // 记录验证结果和性能数据
    console.log('验证结果:', result);
    console.log('验证耗时:', verifyTime, 'ms');
    console.log('客户端计算耗时:', statsData.totalTime, 'ms');
    console.log('难度:', statsData.difficulty);
    console.log('客户端尝试次数:', statsData.nonce);
    
    if (result.valid) {
        // 创建验证cookie，包含hash和nonce
        const cookieData = JSON.stringify({
            hash: hash,
            nonce: nonce,
            ip: clientIp,
            timestamp: Date.now()
        });
        
        // 设置x-hash cookie，有效期24小时
        res.cookie('x-hash', cookieData, {
            maxAge: 24 * 60 * 60 * 1000, // 24小时
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // 在生产环境使用HTTPS
            sameSite: 'strict'
        });
        
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
app.get('/loading', (req, res) => {
    // 获取客户端IP
    let clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
    
    // 处理IP格式
    if (clientIp === '::1') {
        clientIp = '127.0.0.1';
    } else if (clientIp.startsWith('::ffff:')) {
        clientIp = clientIp.substring(7);
    }
    if (clientIp.includes(':')) {
        const lastColonIndex = clientIp.lastIndexOf(':');
        if (clientIp.indexOf(':') === lastColonIndex) {
            clientIp = clientIp.substring(0, lastColonIndex);
        }
    }
    
    // 根据IP计算previousHash
    const previousHash = generatePreviousHash(clientIp);
    
    // 读取HTML模板并注入IP和previousHash
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    let html = fs.readFileSync(htmlPath, 'utf8');
    
    // 替换模板变量
    html = html.replace('{{CLIENT_IP}}', clientIp)
               .replace('{{PREVIOUS_HASH}}', previousHash);
    console.log('Serving page to client IP:', clientIp, 'with Previous Hash:', previousHash);
    
    res.send(html);
});

// 添加受保护的路由
app.get('/', (req, res) => {
    // 验证cookie
    const validation = validateCookie(req, res);
    
    if (validation.valid) {
        // 访问权限验证成功，显示受保护的内容
        res.send(`
            <html>
                <head>
                    <title>受保护的页面</title>
                    <style>
                        body { 
                            font-family: Arial, sans-serif;
                            max-width: 800px;
                            margin: 0 auto;
                            padding: 20px;
                            line-height: 1.6;
                        }
                        .container {
                            padding: 20px;
                            border-radius: 8px;
                            background-color: #f0f8ff;
                            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                        }
                        h1 { color: #2c3e50; }
                        .success { color: #27ae60; }
                        .info { color: #2980b9; }
                        .data { 
                            background-color: #f9f9f9;
                            padding: 10px;
                            border-radius: 4px;
                            border: 1px solid #ddd;
                            margin: 15px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>受保护的资源</h1>
                        <p class="success">✅ 您已通过工作量证明验证，可以访问此受保护的内容。</p>
                        <p>这个页面仅对完成了工作量证明挑战的用户可见。</p>
                        
                        <div class="data">
                            <h3 class="info">您的验证信息</h3>
                            <p>哈希值: ${validation.hash}</p>
                            <p>计算尝试次数: ${validation.nonce}</p>
                            <p>验证IP: ${req.cookies['x-hash'] ? JSON.parse(req.cookies['x-hash']).ip : '未知'}</p>
                        </div>
                        
                        <p>您可以访问网站的所有受保护内容，直到Cookie过期（24小时）。</p>
                        <p><a href="/">返回首页</a></p>
                    </div>
                </body>
            </html>
        `);
    } else {
        // 验证失败，重定向到首页进行验证
        res.redirect('/loading?next=/');
    }
});

// 启动服务器
app.listen(port, () => {
    console.log(`服务器运行在 http://localhost:${port}`);
});