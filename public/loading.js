document.addEventListener('DOMContentLoaded', function() {
    // 获取URL参数
    const urlParams = new URLSearchParams(window.location.search);
    const nextUrl = urlParams.get('next') || '/'; // 默认跳转到根目录
    const difficulty = parseInt(urlParams.get('difficulty') || '4', 10); // 默认难度为4
    
    // 获取客户端IP (在实际环境中应该从服务器获取)
    // 这里仅作为示例，使用一个固定值
    const ipAddress = '127.0.0.1'; 
    
    // 服务器预设的校验哈希和公钥
    // 这些值在实际应用中应该由服务器动态生成并传入
    const previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFVqa0S89jMU2TtFwJoA7ZsOXm
T9d/5+IbqxB2gydx8HVkrtA7JfPElnnU9gGwxiTreWjkDTx8sYEC4K0wGHkzowh1
fOdv747n3pNyun5D4BgiLwV+YT6opRs9D/MNjuXSLGJJ5h8BkHJjBVqykK8LyREv
MXXiB62VWC88fKwMUQIDAQAB
-----END PUBLIC KEY-----`;

    // 设置表单中的next参数
    document.getElementById('next').value = nextUrl;

    // 启动进度条动画
    let progress = 0;
    const progressBar = document.getElementById('progressBar');
    
    // 循序渐进的进度条
    function updateProgress(newProgress) {
        if (newProgress > progress) {
            progress = newProgress;
            progressBar.style.width = progress + '%';
        }
    }

    // 模拟初始加载进度
    setTimeout(() => updateProgress(15), 200);
    setTimeout(() => updateProgress(30), 600);

    // 开始计算工作量证明
    setTimeout(function() {
        try {
            updateProgress(40);
            
            // 计算开始
            const startTime = new Date().getTime();
            const powResult = calculateProofOfWork(ipAddress, previousHash, difficulty, publicKey);
            const totalTime = new Date().getTime() - startTime;
            
            updateProgress(85);

            // 准备提交数据
            document.getElementById('encrypted').value = powResult.encrypted;
            
            // 添加统计数据
            const stats = {
                hashingTime: powResult.hashingTime,
                encryptTime: powResult.encryptTime,
                totalTime: powResult.totalTime,
                nonce: powResult.nonce,
                difficulty: difficulty
            };
            document.getElementById('stats').value = JSON.stringify(stats);
            
            // 完成，展示100%进度
            updateProgress(100);
            
            // 延迟一下，让用户看到100%进度条
            setTimeout(function() {
                // 提交表单
                document.getElementById('powForm').submit();
            }, 500);
            
        } catch (error) {
            console.error('工作量证明计算失败:', error);
            alert('页面加载出错，请重试');
        }
    }, 1000);
});