// script.js - Frontend do Sistema de Esteganografia LSB Avançada

const API_BASE_URL = 'http://localhost:8000';
let currentToken = null;
let currentUser = null;
let lastResultImage = null;
let lastExtractedFile = null;

let authSection, loginForm, registerForm, userSection, mainApp, apiStatusElement;

document.addEventListener('DOMContentLoaded', function() {

    authSection = document.getElementById('authSection');
    loginForm = document.getElementById('loginForm');
    registerForm = document.getElementById('registerForm');
    userSection = document.getElementById('userSection');
    mainApp = document.getElementById('mainApp');
    apiStatusElement = document.getElementById('apiStatus');

    const savedToken = localStorage.getItem('stego_token');
    const savedUser = localStorage.getItem('stego_user');

    if (savedToken && savedUser) {
        currentToken = savedToken;
        currentUser = savedUser;
        showApp();
    }

    setTimeout(checkAPIHealth, 1500);
    setInterval(checkAPIHealth, 5000);

    setupFileListeners();
});

function setupFileListeners() {
    ['coverImage', 'secretFile', 'stegoImage'].forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            input.addEventListener('change', e => {
                const file = e.target.files[0];
                const infoId = id.replace('Image', 'Info').replace('File', 'Info');
                const infoElement = document.getElementById(infoId);
                if (infoElement) {
                    infoElement.textContent = file ? `${file.name} (${formatBytes(file.size)})` : 'Nenhum ficheiro selecionado';
                }
            });
        }
    });
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function checkAPIHealth() {
    try {
        console.log('[HEALTH] Tentando conectar:', API_BASE_URL + '/api/health');
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const response = await fetch(`${API_BASE_URL}/api/health`, {
            method: 'GET',
            mode: 'cors',
            cache: 'no-cache',
            credentials: 'same-origin',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[HEALTH] Resposta:', response.status, response.statusText);

        if (response.ok) {
            if (apiStatusElement) {
                apiStatusElement.textContent = 'Conectado';
                apiStatusElement.className = 'connected';
            }
            console.log('[HEALTH] Sucesso!');
            return true;
        } else {
            if (apiStatusElement) {
                apiStatusElement.textContent = 'Desconectado';
                apiStatusElement.className = 'disconnected';
            }
            console.error('[HEALTH] Falhou - status:', response.status);
        }
    } catch (error) {
        if (apiStatusElement) {
            apiStatusElement.textContent = 'Desconectado';
            apiStatusElement.className = 'disconnected';
        }
        console.error('[HEALTH] Erro:', error.name, error.message);
        if (error.name === 'AbortError') {
            console.error('[HEALTH] Timeout: servidor não respondeu');
        } else if (error.message.includes('Failed to fetch')) {
            console.error('[HEALTH] Falha de rede ou CORS - verifica se o backend está em http://localhost:8000');
        }
    }
    return false;
}

function showTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    const tabElement = document.getElementById(tabId);
    if (tabElement) tabElement.classList.add('active');

    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    const btn = document.querySelector(`.tab-btn[onclick="showTab('${tabId}')"]`);
    if (btn) btn.classList.add('active');

    if (tabId === 'history') loadHistory();
    if (tabId === 'logs') loadLogs();
}

function showLogin() {
    if (loginForm) loginForm.style.display = 'block';
    if (registerForm) registerForm.style.display = 'none';
    if (userSection) userSection.style.display = 'none';
}

function showRegister() {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'block';
    if (userSection) userSection.style.display = 'none';
}

function showApp() {
    if (authSection) authSection.style.display = 'none';
    if (userSection) userSection.style.display = 'block';
    if (mainApp) mainApp.style.display = 'block';
    const userElem = document.getElementById('currentUser');
    if (userElem) userElem.textContent = currentUser || 'Utilizador';
}

function showAlert(message, type = 'info') {
    const statusDiv = document.createElement('div');
    statusDiv.className = `status ${type}`;
    statusDiv.textContent = message;
    document.body.appendChild(statusDiv);
    setTimeout(() => statusDiv.remove(), 7000);
}

async function login() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value;

    if (!username || !password) {
        showAlert('Preencha usuário e senha', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok && data.access_token) {
            currentToken = data.access_token;
            currentUser = data.username;
            localStorage.setItem('stego_token', currentToken);
            localStorage.setItem('stego_user', currentUser);
            showApp();
            showAlert(`Bem-vindo, ${currentUser}!`, 'success');
        } else {
            showAlert(data.error || 'Credenciais inválidas', 'error');
        }
    } catch (err) {
        console.error('Erro no login:', err);
        showAlert('Erro ao conectar ao servidor. Verifique se o backend está a correr.', 'error');
    }
}

async function register() {
    const username = document.getElementById('regUsername')?.value.trim();
    const password = document.getElementById('regPassword')?.value;
    const email = document.getElementById('regEmail')?.value.trim();

    if (!username || !password) {
        showAlert('Usuário e senha são obrigatórios', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, email })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showAlert('Conta criada com sucesso! Pode fazer login agora.', 'success');
            showLogin();
        } else {
            showAlert(data.message || 'Erro ao registrar. O utilizador já pode existir.', 'error');
        }
    } catch (err) {
        console.error('Erro no register:', err);
        showAlert('Erro ao conectar ao servidor', 'error');
    }
}

function logout() {
    localStorage.removeItem('stego_token');
    localStorage.removeItem('stego_user');
    currentToken = null;
    currentUser = null;
    showLogin();
    showAlert('Sessão terminada com sucesso', 'info');
}

async function deleteAccount() {
    if (!confirm('Tem a certeza que deseja eliminar a sua conta permanentemente? Esta ação não pode ser desfeita.')) {
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/account`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (response.ok && data.success) {
            showAlert('Conta eliminada com sucesso. Até breve!', 'success');
            logout();
        } else {
            showAlert(data.error || 'Erro ao eliminar conta', 'error');
        }
    } catch (err) {
        console.error('Erro ao eliminar conta:', err);
        showAlert('Erro ao conectar ao servidor', 'error');
    }
}

async function processEncode() {
    if (!currentToken) {
        showAlert('Faça login primeiro', 'error');
        return;
    }

    const button = document.querySelector('.btn-process[onclick="processEncode()"]');
    if (button) button.disabled = true;

    const coverFile = document.getElementById('coverImage')?.files[0];
    const secretFile = document.getElementById('secretFile')?.files[0];
    const key = document.getElementById('encodeKey')?.value.trim();
    const compress = document.getElementById('compressOption')?.checked;

    if (!coverFile || !secretFile || !key) {
        showAlert('Selecione imagem de cobertura, ficheiro a ocultar e insira a chave', 'error');
        if (button) button.disabled = false;
        return;
    }

    showAlert('A processar ocultação... (pode demorar alguns segundos)', 'info');

    const formData = new FormData();
    formData.append('cover_image', await fileToBase64(coverFile));
    formData.append('secret_data', await fileToBase64(secretFile));
    formData.append('secret_filename', secretFile.name);
    formData.append('key', key);
    formData.append('compress', compress ? 'true' : 'false');

    try {
        const response = await fetch(`${API_BASE_URL}/api/steganography/encode`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            lastResultImage = `data:image/png;base64,${data.image}`;
            const link = document.createElement('a');
            link.href = lastResultImage;
            link.download = 'imagem_esteganografada.png';
            link.click();

            showAlert('Imagem gerada com sucesso! Ficheiro oculto com segurança.', 'success');
        } else {
            showAlert(data.error || 'Não foi possível ocultar o ficheiro. Verifique o tamanho ou capacidade da imagem.', 'error');
        }
    } catch (err) {
        showAlert('Erro ao comunicar com o servidor. Tente novamente.', 'error');
    } finally {
        if (button) button.disabled = false;
    }
}

async function processDecode() {
    if (!currentToken) {
        showAlert('Faça login primeiro', 'error');
        return;
    }

    const button = document.querySelector('.btn-process[onclick="processDecode()"]');
    if (button) button.disabled = true;

    const stegoFile = document.getElementById('stegoImage')?.files[0];
    const key = document.getElementById('decodeKey')?.value.trim();

    if (!stegoFile || !key) {
        showAlert('Selecione a imagem esteganografada e insira a chave', 'error');
        if (button) button.disabled = false;
        return;
    }

    showAlert('A processar extração... (pode demorar alguns segundos)', 'info');

    const formData = new FormData();
    formData.append('stego_image', await fileToBase64(stegoFile));
    formData.append('key', key);

    try {
        const response = await fetch(`${API_BASE_URL}/api/steganography/decode`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${currentToken}` },
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            const binary = atob(data.data);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            const blob = new Blob([bytes], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);

            const link = document.createElement('a');
            link.href = url;
            link.download = data.filename;
            link.click();

            URL.revokeObjectURL(url);

            showAlert(`Ficheiro "${data.filename}" extraído com sucesso! (Compressão usada: ${data.compressed ? 'Sim' : 'Não'})`, 'success');
        } else {
            let errorMsg = data.error || 'Não foi possível extrair os dados.';

            if (errorMsg.includes('Hash inválido') || errorMsg.includes('chave incorreta')) {
                errorMsg = 'Chave secreta incorreta ou imagem não contém dados ocultos.';
            } else if (errorMsg.includes('Dados insuficientes') || errorMsg.includes('irrealista')) {
                errorMsg = 'Imagem inválida ou chave incorreta. Certifique-se de usar a mesma chave usada na ocultação e a imagem original gerada (sem alterações).';
            } else if (errorMsg.includes('não encontrou payload')) {
                errorMsg = 'Não foi possível encontrar dados ocultos na imagem.';
            }

            showAlert(errorMsg, 'error');
        }
    } catch (err) {
        console.error('Erro no decode:', err);
        showAlert('Erro ao comunicar com o servidor. Verifique se o backend está a correr.', 'error');
    } finally {
        if (button) button.disabled = false;
    }
}

async function loadHistory() {
    if (!currentToken) return;

    try {
        const response = await fetch(`${API_BASE_URL}/api/history`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        if (!response.ok) throw new Error(await response.text());

        const data = await response.json();
        const list = document.getElementById('historyList');
        if (list) list.innerHTML = '';

        if (data.history.length === 0) {
            if (list) list.innerHTML = '<p class="no-data">Nenhum registo no histórico ainda.</p>';
            return;
        }

        data.history.forEach(entry => {
            const item = document.createElement('div');
            item.className = `history-item ${entry.status}`;
            item.innerHTML = `
                <div class="history-item-header">
                    <span>${entry.operation_type}</span>
                    <span>${new Date(entry.operation_date).toLocaleString('pt-PT')}</span>
                </div>
                <div class="history-item-details">
                    <p><strong>Ficheiro:</strong> ${entry.original_filename || '-'}</p>
                    <p><strong>Resultado:</strong> ${entry.result_filename || '-'}</p>
                    <p><strong>Tamanho:</strong> ${entry.file_size ? formatBytes(entry.file_size) : '-'}</p>
                    <p><strong>Estado:</strong> ${entry.status}</p>
                </div>
            `;
            if (list) list.appendChild(item);
        });
    } catch (err) {
        showAlert('Erro ao carregar histórico: ' + err.message, 'error');
    }
}

async function loadLogs() {
    if (!currentToken) {
        showAlert('Faça login primeiro', 'error');
        return;
    }

    const button = document.querySelector('.btn-refresh[onclick="loadLogs()"]');
    if (button) button.disabled = true;

    const list = document.getElementById('logsList');
    if (list) list.innerHTML = '<p>Carregando logs...</p>';

    try {
        const response = await fetch(`${API_BASE_URL}/api/logs`, {
            headers: { 'Authorization': `Bearer ${currentToken}` }
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'Erro ao carregar logs');
        }

        const data = await response.json();
        if (list) list.innerHTML = '';

        if (!data.logs || data.logs.length === 0) {
            if (list) list.innerHTML = '<p class="no-data">Nenhum log de atividade ainda.</p>';
            return;
        }

        data.logs.forEach(log => {
            const item = document.createElement('div');
            item.className = 'log-item';
            if (log.username === 'admin') item.classList.add('admin');
            let userDisplay = log.username || 'Sistema';
            if (log.user_id === 0 && log.action.includes('FAILED')) {
                userDisplay = 'Tentativa falhada';
            }
            item.innerHTML = `
                <div class="log-item-header">
                    <span>${log.action}</span>
                    <span>${new Date(log.timestamp).toLocaleString('pt-PT')}</span>
                </div>
                <div class="log-item-details">
                    <p><strong>Utilizador:</strong> ${userDisplay}</p>
                    <p><strong>Detalhes:</strong> ${log.details || '-'}</p>
                    <p><strong>IP:</strong> ${log.ip_address || 'Desconhecido'}</p>
                </div>
            `;
            if (list) list.appendChild(item);
        });
    } catch (err) {
        showAlert('Erro ao carregar logs: ' + err.message, 'error');
        if (list) list.innerHTML = '<p class="no-data">Erro ao carregar logs.</p>';
    } finally {
        if (button) button.disabled = false;
    }
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.onerror = error => reject(error);
    });
}

showTab('encode');