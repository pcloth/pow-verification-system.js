/**
 * 工作量证明实现与加密
 * 兼容IE11版本
 */

// 工作量证明函数
function calculateProofOfWork(ipaddress, previousHash, difficulty, publicString) {
    var nonce = 1;
    var hash = '';
    var prefix = '';
    var startTime = new Date().getTime();
    
    // 创建一个长度等于难度的零字符串
    for (var i = 0; i < difficulty; i++) {
        prefix += '0';
    }
    
    // 不断计算哈希值，直到找到一个满足前缀要求的哈希
    do {
        hash = CryptoJS.SHA256(ipaddress + previousHash + nonce).toString();
        nonce++;
        
        // 添加简单的超时保护，防止无限循环
        if (nonce > 10000000 || new Date().getTime() - startTime > 30000) {
            throw new Error('工作量证明计算超时。请尝试降低难度。');
        }
    } while (hash.substring(0, difficulty) !== prefix);
    
    var hashingTime = new Date().getTime() - startTime;
    console.log('经过 ' + (nonce - 1) + ' 次尝试后找到有效哈希，计算耗时: ' + hashingTime + 'ms');
    
    // 创建要加密的数据
    var timestamp = new Date().getTime();
    var payload = ipaddress + ',' + hash + ',' + timestamp + ',' + (nonce - 1);
    
    // 记录加密开始时间
    var encryptStartTime = new Date().getTime();
    
    // 使用公钥加密数据
    var encrypted = encryptWithPublicKey(payload, publicString);
    
    var encryptTime = new Date().getTime() - encryptStartTime;
    var totalTime = new Date().getTime() - startTime;
    
    return {
        nonce: nonce - 1,
        hash: hash,
        encrypted: encrypted,
        timestamp: timestamp,
        hashingTime: hashingTime,
        encryptTime: encryptTime,
        totalTime: totalTime
    };
}

// 使用公钥加密数据的函数
function encryptWithPublicKey(data, publicKeyString) {
    try {
        var encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKeyString);
        var encrypted = encrypt.encrypt(data);
        return encrypted;
    } catch (e) {
        console.error('加密错误:', e);
        throw new Error('数据加密失败: ' + e.message);
    }
}

// 使用私钥解密并验证数据的函数
function decryptAndVerify(encryptedData, privateKeyString, ipaddress, previousHash, difficulty) {
    try {
        var startTime = new Date().getTime();
        
        // 解密数据
        var decryptStartTime = new Date().getTime();
        var decrypt = new JSEncrypt();
        decrypt.setPrivateKey(privateKeyString);
        var decrypted = decrypt.decrypt(encryptedData);
        var decryptTime = new Date().getTime() - decryptStartTime;
        
        if (!decrypted) {
            return {
                valid: false,
                reason: '数据解密失败',
                decryptTime: decryptTime
            };
        }
        
        // 解析解密后的数据
        var parts = decrypted.split(',');
        if (parts.length !== 4) {
            return {
                valid: false,
                reason: '数据格式无效',
                decryptTime: decryptTime
            };
        }
        
        var decryptedIp = parts[0];
        var hash = parts[1];
        var timestamp = parts[2];
        var nonce = parseInt(parts[3], 10);
        
        // 验证IP地址
        if (decryptedIp !== ipaddress) {
            return {
                valid: false,
                reason: 'IP地址不匹配',
                decryptTime: decryptTime
            };
        }
        
        // 验证哈希前缀是否符合难度要求
        var prefix = '';
        for (var i = 0; i < difficulty; i++) {
            prefix += '0';
        }
        
        if (hash.substring(0, difficulty) !== prefix) {
            return {
                valid: false,
                reason: '哈希不符合难度要求',
                decryptTime: decryptTime
            };
        }
        
        // 记录哈希验证开始时间
        var verifyHashStartTime = new Date().getTime();
        
        // 直接验证哈希是否有效，使用客户端提供的nonce
        var calculatedHash = CryptoJS.SHA256(ipaddress + previousHash + nonce).toString();
        var verifyHashTime = new Date().getTime() - verifyHashStartTime;
        
        if (calculatedHash !== hash) {
            return {
                valid: false,
                reason: '哈希验证失败',
                decryptTime: decryptTime,
                verifyHashTime: verifyHashTime
            };
        }
        
        // 可选：验证时间戳是否在合理范围内
        var currentTime = new Date().getTime();
        var timeDiff = currentTime - parseInt(timestamp, 10);
        if (timeDiff > 3600000) { // 1小时过期
            return {
                valid: false,
                reason: '工作量证明已过期',
                decryptTime: decryptTime,
                verifyHashTime: verifyHashTime
            };
        }
        
        var totalTime = new Date().getTime() - startTime;
        
        return {
            valid: true,
            ip: decryptedIp,
            hash: hash,
            timestamp: timestamp,
            nonce: nonce,
            decryptTime: decryptTime,
            verifyHashTime: verifyHashTime,
            totalTime: totalTime
        };
    } catch (e) {
        console.error('验证错误:', e);
        return {
            valid: false,
            reason: '验证错误: ' + e.message
        };
    }
}