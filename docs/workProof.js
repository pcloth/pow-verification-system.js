/**
 * 工作量证明实现
 */

// 工作量证明函数
function calculateProofOfWork(ipaddress, previousHash, difficulty) {
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
    
    // 创建要发送的数据
    var timestamp = new Date().getTime();
    var payload = ipaddress + ',' + hash + ',' + timestamp + ',' + (nonce - 1);
    
    var totalTime = new Date().getTime() - startTime;
    
    return {
        nonce: nonce - 1,
        hash: hash,
        payload: payload,
        timestamp: timestamp,
        hashingTime: hashingTime,
        totalTime: totalTime
    };
}


// 验证数据的函数
function verifyProofOfWork(payload, ipaddress, previousHash, difficulty) {
    try {
        var startTime = new Date().getTime();
        // 直接解析明文payload
        var parts = payload.split(',');
        if (parts.length !== 4) {
            return {
                valid: false,
                reason: '数据格式无效'
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
                reason: 'IP地址不匹配'
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
                reason: '哈希不符合难度要求'
            };
        }
        // 验证哈希是否有效
        var verifyHashStartTime = new Date().getTime();
        var calculatedHash = CryptoJS.SHA256(ipaddress + previousHash + nonce).toString();
        var verifyHashTime = new Date().getTime() - verifyHashStartTime;
        if (calculatedHash !== hash) {
            return {
                valid: false,
                reason: '哈希验证失败',
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