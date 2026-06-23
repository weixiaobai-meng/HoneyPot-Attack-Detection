document.addEventListener('DOMContentLoaded', function() {
    const fileTableBody = document.getElementById('file-table-body');
    const generateBtn = document.getElementById('generate-btn');
    const templateSelect = document.getElementById('template-select');
    const selectAllCheckbox = document.getElementById('select-all');

    // “生成”按钮点击事件
    generateBtn.addEventListener('click', function() {
        const selectedFileIds = Array.from(document.querySelectorAll('.file-checkbox:checked'))
            .map(checkbox => checkbox.getAttribute('data-file-id'));
        
        const selectedTemplate = templateSelect.value;
        
        if (selectedFileIds.length === 0) {
            alert("请至少选择一个文件！");
            return;
        }

        // 向后端新创建的API发送POST请求
        fetch('/honeypot/generate_page', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                file_ids: selectedFileIds,
                template_name: selectedTemplate
            })
        })
        .then(response => response.json())
        .then(result => {
            if (result.code === 0) {
                alert(result.message + "，部署路径：" + result.data.deploy_path);
            } else {
                alert("生成失败：" + result.message);
            }
        })
        .catch(error => {
            console.error('网络或服务器错误：', error);
            alert("生成页面时发生错误，请检查控制台。");
        });
    });

    // “全选/取消全选”功能
    selectAllCheckbox.addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('.file-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
        });
    });

    // 这里不再需要调用 fetchFiles()，因为文件列表已经由后端渲染完成。
});