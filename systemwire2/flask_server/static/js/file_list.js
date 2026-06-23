document.addEventListener('DOMContentLoaded', function() {
    // ---------------- 原有删除功能 ----------------
    const deleteForms = document.querySelectorAll('.delete-form');
    deleteForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            const id = form.querySelector('input[name="id"]').value;
            fetch('/file/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: id })
            })
            .then(resp => resp.json())
            .then(data => {
                if (data.code === 0) {
                    alert('文件删除成功！');
                    location.reload();
                } else alert('错误: ' + data.message);
            })
            .catch(err => { alert('请求失败'); console.error(err); location.reload(); });
        });
    });

    // ---------------- 下发文件功能 ----------------
    window.sendFileToAgent = function(fileId, filename) {
        document.getElementById('sendFileId').value = fileId;
        document.getElementById('sendFileName').textContent = filename;
        document.getElementById('sendModal').style.display = 'block';
        fetchAgents();
    }

    window.closeSendModal = function() {
        document.getElementById('sendModal').style.display = 'none';
    }

    async function fetchAgents() {
        const agentSelect = document.getElementById('agentSelect');
        agentSelect.innerHTML = '<option>加载中...</option>';
        try {
            const resp = await fetch('/api/agent/list'); // 返回 JSON
            const data = await resp.json();
            agentSelect.innerHTML = '';
            if (data.agents_infos && data.agents_infos.length > 0) {
                data.agents_infos.forEach(agent => {
                    const opt = document.createElement('option');
                    opt.value = agent.id;
                    opt.textContent = `${agent.name} (ID: ${agent.id})`;
                    agentSelect.appendChild(opt);
                });
            } else {
                const opt = document.createElement('option');
                opt.textContent = '没有在线 Agent';
                agentSelect.appendChild(opt);
            }
        } catch (err) {
            console.error(err);
            agentSelect.innerHTML = '<option>获取失败</option>';
        }
    }

    window.sendFileToAgentFromModal = async function() {
        const fileId = document.getElementById('sendFileId').value;
        const agentId = document.getElementById('agentSelect').value;
        const remotePath = document.getElementById('remotePath').value;

        if (!agentId || !remotePath) {
            alert('请选择 Agent 并填写路径');
            return;
        }

        const payload = {
            client_id: agentId,
            command_type: "send_file",
            command_data: ({ file_id: fileId, remote_path: remotePath })
        };

        try {
            const resp = await fetch('/agent/command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const result = await resp.json();
            alert(result.message);
            closeSendModal();
        } catch (err) {
            console.error(err);
            alert('命令发送失败');
        }
    }
});
