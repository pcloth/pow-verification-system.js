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
        // 确保数据不超过RSA密钥允许的长度（密钥长度/8 - 11）
        // 假设使用的是1024位的密钥，最大消息长度约为117字节
        if (data.length > 117) {
            console.warn('数据长度过长，可能会导致加密失败。当前长度: ' + data.length);
        }
        
        // 创建JSEncrypt实例并配置
        var encrypt = new JSEncrypt();
        encrypt.setPublicKey(publicKeyString);
        
        // 在控制台输出加密前的数据（方便调试）
        console.log('加密前数据:', data);
        console.log('加密前数据长度:', data.length);
        
        // 执行加密
        var encrypted = encrypt.encrypt(data);
        
        if (!encrypted) {
            throw new Error('加密结果为空，可能是数据太长或密钥配置问题');
        }
        
        console.log('加密后数据长度:', encrypted.length);
        return encrypted;
    } catch (e) {
        console.error('加密错误:', e);
        throw new Error('数据加密失败: ' + e.message);
    }
}