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