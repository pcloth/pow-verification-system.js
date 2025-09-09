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
    
    var timestamp = new Date().getTime();
    var totalTime = new Date().getTime() - startTime;
    
    return {
        nonce: nonce - 1,
        hash: hash,
        timestamp: timestamp,
        hashingTime: hashingTime,
        totalTime: totalTime
    };
}