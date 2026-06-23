document.getElementById('uploadForm').addEventListener('submit', function(event) {
    event.preventDefault(); // 阻止表单的默认提交行为

    // 获取表单中的值
    const honeypoint_name = document.getElementById('honeypoint_name').value;
    const message = document.getElementById('message').value;
    const server = document.getElementById('server').value;
    const source = document.getElementById('source').value;
    const format = document.getElementById('format').value;
    const email = document.getElementById('email').value;
    const fileInput = document.getElementById('file');
    const file = fileInput.files[0];

    if (!file) {
        alert('请上传文件！');
        return;
    }

    // 构造 JSON 数据
    const data = JSON.stringify({
        honeypoint_name: honeypoint_name,
        message: message,
        server: server,
        source: source,
        format: format,
        email:email
    });

    // 构造 FormData 对象
    const formData = new FormData();
    formData.append('data', data); // 将 JSON 数据作为表单字段
    formData.append('file', file); // 将文件作为表单字段

    // 发送请求
    fetch('/file/create', {
        method: 'POST',
        headers: {
            'user-key': 'example_user_key', // 设置 user_key
        },
        credentials: 'include', // 允许发送和接收 Cookies
        body: formData
    })
    .then(response => {
        // 检查响应的 Content-Type 确保它是 JSON 格式
        if (!response.ok) {
            throw new Error('网络响应失败');
        }
        return response.json();
    })
    .then(data => {
        if (data.code === 0) {
            // 处理成功的情况
            alert('文件创建成功！');
        } else {
            // 处理错误情况，展示错误信息
            alert('错误: ' + data.message);
        }
    })
    .catch((error) => {
        console.error('请求失败:', error);
        alert('请求失败，请稍后重试。');
    });
});