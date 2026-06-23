// Agent 管理页交互逻辑
function openAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'block';
}

function closeAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'none';
}

function openCommandModal(agentId, agentName) {
    document.getElementById('command_agent_id').value = agentId;
    document.getElementById('commandModal').style.display = 'block';
    updateCommandType();
}

function closeCommandModal() {
    document.getElementById('commandModal').style.display = 'none';
}

function submitAddAgent() {
    const clientName = document.getElementById('client_name').value;
    const opeSys = document.getElementById('ope_sys').value;
    const ip = document.getElementById('ip').value || '';

    fetch('/agent/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clientName, opeSys, ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.code === 0) {
            alert('Agent 添加成功！');
            closeAddAgentModal();
            location.reload();
        } else {
            alert('添加失败：' + data.message);
        }
    })
    .catch(error => alert('请求失败：' + error));
}

function selectedHoneyType() {
    return document.getElementById('honey_type').value;
}

function updateCommandType() {
    const honeyType = selectedHoneyType();
    const commandType = document.getElementById('command_type');
    const accountFields = document.getElementById('accountFields');
    const fileFields = document.getElementById('fileFields');
    const jsField = document.getElementById('jsField');

    const typeMap = {
        file: { value: '6', text: '6 - deploy_file_honeypot' },
        account: { value: '4', text: '4 - add_account' },
        parasitic: { value: '7', text: '7 - deploy_parasitic' }
    };
    const option = typeMap[honeyType] || typeMap.file;
    commandType.innerHTML = `<option value="${option.value}">${option.text}</option>`;
    commandType.value = option.value;

    accountFields.style.display = honeyType === 'account' ? 'block' : 'none';
    fileFields.style.display = honeyType === 'file' ? 'block' : 'none';
    jsField.style.display = honeyType === 'parasitic' ? 'block' : 'none';
}

function buildAccountPayload() {
    const accountType = document.getElementById('account_type').value;
    const host = document.getElementById('account_ip').value.trim();
    const port = document.getElementById('account_port').value.trim();
    const username = document.getElementById('account_username').value.trim();
    const password = document.getElementById('account_password').value.trim();

    if (!accountType || !host || !port) throw new Error('账户蜜点需要类型、IP/主机和端口。');
    const portNumber = Number(port);
    if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) throw new Error('端口必须是 1-65535 的整数。');
    if (accountType === 'openvpn') return `openvpn:${host}:${port}`;
    if (!username || !password) throw new Error('Xshell / FinalShell 需要用户名和密码。');
    return `${accountType}:${host}:${port}:${username}:${password}`;
}

function buildFilePayload() {
    const raw = document.getElementById('file_payload').value.trim();
    if (!raw) throw new Error('文件蜜点需要 JSON 参数。');
    let payload;
    try {
        payload = JSON.parse(raw);
    } catch (error) {
        throw new Error('文件蜜点 JSON 格式不正确：' + error.message);
    }
    return JSON.stringify(payload);
}

function buildParasiticPayload() {
    const targetDir = document.getElementById('target_dir').value.trim();
    const jsBundle = document.getElementById('js_bundle').value;
    const jsUrl = document.getElementById('js_url').value.trim();
    let injectMode = document.getElementById('inject_mode').value;

    if (!targetDir) throw new Error('寄生蜜点需要目标网站目录。');
    if (jsBundle === 'builtin_root_js') injectMode = 'inline';
    if (!jsBundle && !jsUrl) throw new Error('自定义 JS 模式需要填写 JS URL。');

    return JSON.stringify({
        target_dir: targetDir,
        js_bundle: jsBundle,
        js_url: jsBundle ? '' : jsUrl,
        js_content: '',
        inject_mode: injectMode,
        backup: true
    });
}

function submitCommand() {
    const agentId = document.getElementById('command_agent_id').value;
    const honeyType = selectedHoneyType();
    const commandType = Number(document.getElementById('command_type').value);
    let commandData = '';

    try {
        if (honeyType === 'account') commandData = buildAccountPayload();
        else if (honeyType === 'parasitic') commandData = buildParasiticPayload();
        else commandData = buildFilePayload();
    } catch (error) {
        alert(error.message);
        return;
    }

    fetch('/api/agent/command', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: agentId, cmd_type: commandType, cmd_data: commandData })
    })
    .then(response => response.json())
    .then(data => {
        if (data.code === 0) {
            alert(`命令发布成功！cmd_id=${data.data.cmd_id}`);
            closeCommandModal();
            location.reload();
        } else {
            alert('命令发布失败：' + data.message);
        }
    })
    .catch(error => alert('请求失败：' + error));
}

document.addEventListener('DOMContentLoaded', () => {
    const honeyType = document.getElementById('honey_type');
    if (honeyType) updateCommandType();
});
