const tokenKey = "chatbot_token";
let token = localStorage.getItem(tokenKey) || "";
let currentConversationId = "";
let isSending = false;
const conversationStatuses = new Map();
const DRAFT_STATUS_KEY = "__draft__";

const authPanel = document.getElementById("authPanel");
const appPanel = document.getElementById("appPanel");
const authMsg = document.getElementById("authMsg");
const statusEl = document.getElementById("status");
const chatEl = document.getElementById("chat");
const convListEl = document.getElementById("convList");
const whoamiEl = document.getElementById("whoami");
const messageEl = document.getElementById("message");
const sendBtn = document.getElementById("sendBtn");
const memoriesBtn = document.getElementById("memoriesBtn");
const memoryModalOverlay = document.getElementById("memoryModalOverlay");
const memoryCloseBtn = document.getElementById("memoryCloseBtn");
const memorySearchInput = document.getElementById("memorySearchInput");
const memoryRefreshBtn = document.getElementById("memoryRefreshBtn");
const memoryListEl = document.getElementById("memoryList");

let memoryItems = [];

function statusKey(conversationId) {
  return conversationId || DRAFT_STATUS_KEY;
}

function setConversationStatus(conversationId, text) {
  const key = statusKey(conversationId);
  if (text) {
    conversationStatuses.set(key, text);
  } else {
    conversationStatuses.delete(key);
  }

  if (key === statusKey(currentConversationId)) {
    statusEl.textContent = text || "";
  }
}

function syncStatusForCurrentConversation() {
  statusEl.textContent = conversationStatuses.get(statusKey(currentConversationId)) || "";
}

function setStatus(text) {
  setConversationStatus(currentConversationId, text);
}

function setAuthMsg(text) { authMsg.textContent = text || ""; }

function formatMemoryUpdates(memoryUpdates) {
  if (!memoryUpdates) return;
  const remembered = memoryUpdates.remembered || [];
  const forgotten = memoryUpdates.forgotten || [];
  const updated = memoryUpdates.updated || [];

  const chunks = [];
  if (remembered.length) chunks.push(`已记住: ${remembered.join("；")}`);
  if (updated.length) chunks.push(`已更新: ${updated.join("；")}`);
  if (forgotten.length) chunks.push(`已忘记: ${forgotten.join("、")}`);
  if (chunks.length) return chunks.join(" | ");
}

function headers() {
  const base = { "Content-Type": "application/json" };
  if (token) base.Authorization = `Bearer ${token}`;
  return base;
}

async function api(path, method = "GET", body) {
  const res = await fetch(path, {
    method,
    headers: headers(),
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function bubble(text, role = "bot") {
  const div = document.createElement("div");
  div.className = `bubble ${role}`;
  div.textContent = text;
  chatEl.appendChild(div);
  chatEl.scrollTop = chatEl.scrollHeight;
  return div;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderMemoryList(items) {
  if (!items.length) {
    memoryListEl.innerHTML = '<div class="memory-empty">暂无记忆</div>';
    return;
  }

  const rows = items
    .map((item) => {
      const text = `${item.label}: ${item.value}`;
      return `
        <div class="memory-item" data-memory-id="${item.id}">
          <div>
            <div class="memory-item-text">${escapeHtml(text)}</div>
            <div class="memory-item-meta">更新于 ${escapeHtml(item.updated_at || "-")}</div>
          </div>
          <button class="memory-delete" data-memory-id="${item.id}" title="删除这条记忆">×</button>
        </div>
      `;
    })
    .join("");

  memoryListEl.innerHTML = rows;
}

function applyMemoryFilter() {
  const keyword = (memorySearchInput.value || "").trim().toLowerCase();
  if (!keyword) {
    renderMemoryList(memoryItems);
    return;
  }

  const filtered = memoryItems.filter((item) => {
    const text = `${item.label} ${item.value}`.toLowerCase();
    return text.includes(keyword);
  });
  renderMemoryList(filtered);
}

async function refreshMemories() {
  const data = await api("/api/memories");
  memoryItems = data.items || [];
  applyMemoryFilter();
}

async function openMemories() {
  memoryModalOverlay.classList.remove("hidden");
  memorySearchInput.value = "";
  memoryListEl.innerHTML = '<div class="memory-empty">加载中...</div>';
  try {
    await refreshMemories();
  } catch (err) {
    memoryListEl.innerHTML = `<div class="memory-empty">加载失败：${escapeHtml(err.message)}</div>`;
  }
}

function closeMemories() {
  memoryModalOverlay.classList.add("hidden");
}

async function deleteMemoryById(memoryId) {
  try {
    await api(`/api/memories/${memoryId}`, "DELETE");
    memoryItems = memoryItems.filter((item) => item.id !== memoryId);
    applyMemoryFilter();
    setStatus("记忆已删除");
  } catch (err) {
    setStatus(`删除记忆失败：${err.message}`);
  }
}

function renderConversations(items) {
  convListEl.innerHTML = "";
  if (!items.length) {
    const p = document.createElement("div");
    p.className = "muted";
    p.textContent = "暂无会话";
    convListEl.appendChild(p);
    return;
  }

  for (const item of items) {
    const btn = document.createElement("button");
    btn.className = `conv-item ${item.id === currentConversationId ? "active" : ""}`;
    btn.textContent = item.title;
    btn.onclick = () => loadConversation(item.id);
    convListEl.appendChild(btn);
  }
}

async function refreshConversations() {
  const data = await api("/api/conversations");
  renderConversations(data.items || []);
  if (!currentConversationId && data.items && data.items.length) {
    await loadConversation(data.items[0].id);
  }
}

async function loadConversation(id) {
  const data = await api(`/api/conversations/${id}/messages`);
  currentConversationId = id;
  syncStatusForCurrentConversation();
  chatEl.innerHTML = "";
  for (const msg of data.messages || []) {
    if (msg.role === "system") continue;
    bubble(msg.content, msg.role === "user" ? "user" : "bot");
  }
  await refreshConversations();
}

function parseSseBlock(block) {
  const lines = block.split("\n");
  let event = "message";
  const dataLines = [];
  for (const line of lines) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  let data = {};
  if (dataLines.length) {
    try {
      data = JSON.parse(dataLines.join("\n"));
    } catch {
      data = {};
    }
  }
  return { event, data };
}

async function sendMessage() {
  const text = messageEl.value.trim();
  if (!text || isSending) return;

  isSending = true;
  sendBtn.disabled = true;
  bubble(text, "user");
  messageEl.value = "";
  const requestedConversationId = currentConversationId;
  let streamConversationId = requestedConversationId;
  setConversationStatus(streamConversationId, "生成中...");

  const botBubble = bubble("", "bot");
  let gotDelta = false;

  try {
    const res = await fetch("/api/chat/stream", {
      method: "POST",
      headers: { ...headers(), Accept: "text/event-stream" },
      body: JSON.stringify({
        message: text,
        conversation_id: currentConversationId,
      }),
    });

    if (!res.ok || !res.body) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    const handleEvent = (evt) => {
      if (evt.event === "meta" && evt.data.conversation_id) {
        streamConversationId = evt.data.conversation_id;
        if (!requestedConversationId) {
          setConversationStatus("", "");
        }
        setConversationStatus(streamConversationId, "生成中...");
        if (!requestedConversationId && !currentConversationId) {
          currentConversationId = streamConversationId;
          syncStatusForCurrentConversation();
        }
      }

      if (evt.event === "delta") {
        gotDelta = true;
        botBubble.textContent += evt.data.text || "";
        chatEl.scrollTop = chatEl.scrollHeight;
      }

      if (evt.event === "done") {
        const latency = evt.data.latency || "-";
        const memoryText = formatMemoryUpdates(evt.data.memory_updates);
        const doneText = memoryText
          ? `完成，耗时 ${latency}s | ${memoryText}`
          : `完成，耗时 ${latency}s`;
        setConversationStatus(streamConversationId, doneText);
      }

      if (evt.event === "error") {
        if (!gotDelta) {
          botBubble.className = "bubble error";
          botBubble.textContent = `错误：${evt.data.message || "未知错误"}`;
        } else {
          bubble(`错误：${evt.data.message || "未知错误"}`, "error");
        }
        setConversationStatus(streamConversationId, "请求失败");
      }
    };

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";

      for (const part of parts) {
        const trimmed = part.trim();
        if (!trimmed) continue;
        handleEvent(parseSseBlock(trimmed));
      }
    }

    const tail = buffer.trim();
    if (tail) {
      handleEvent(parseSseBlock(tail));
    }

    if (!gotDelta && !botBubble.textContent.trim()) {
      botBubble.textContent = "(空响应)";
    }
    await refreshConversations();

  } catch (err) {
    botBubble.className = "bubble error";
    botBubble.textContent = `错误：${err.message}`;
    setStatus("请求失败");
  } finally {
    isSending = false;
    sendBtn.disabled = false;
    messageEl.focus();
  }
}

async function handleLogin() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) return setAuthMsg("请输入用户名和密码");

  try {
    const data = await api("/api/login", "POST", { username, password });
    token = data.token;
    localStorage.setItem(tokenKey, token);
    await enterApp();
  } catch (err) {
    setAuthMsg(err.message);
  }
}

async function handleRegister() {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  if (!username || !password) return setAuthMsg("请输入用户名和密码");

  try {
    await api("/api/register", "POST", { username, password });
    setAuthMsg("注册成功，请点击登录");
  } catch (err) {
    setAuthMsg(err.message);
  }
}

async function enterApp() {
  try {
    const me = await api("/api/me");
    authPanel.classList.add("hidden");
    appPanel.classList.remove("hidden");
    whoamiEl.textContent = `用户：${me.username}`;
    chatEl.innerHTML = "";
    currentConversationId = "";
    await refreshConversations();
    if (!currentConversationId) {
      bubble("你好，点击“新建”开始会话。", "bot");
    }
  } catch (_) {
    localStorage.removeItem(tokenKey);
    token = "";
    authPanel.classList.remove("hidden");
    appPanel.classList.add("hidden");
  }
}

async function newConversation() {
  try {
    const data = await api("/api/conversations", "POST", { title: "新会话" });
    await refreshConversations();
    await loadConversation(data.id);
    setStatus("已创建新会话");
  } catch (err) {
    setStatus(err.message);
  }
}

async function renameConversation() {
  if (!currentConversationId) return;
  const name = prompt("请输入新会话名称");
  if (!name) return;

  try {
    await api(`/api/conversations/${currentConversationId}/rename`, "POST", { title: name });
    await refreshConversations();
    setStatus("重命名成功");
  } catch (err) {
    setStatus(err.message);
  }
}

async function deleteConversation() {
  if (!currentConversationId) return;
  if (!confirm("确认删除当前会话？")) return;

  try {
    await api(`/api/conversations/${currentConversationId}`, "DELETE");
    currentConversationId = "";
    chatEl.innerHTML = "";
    await refreshConversations();
    setStatus("已删除会话");
  } catch (err) {
    setStatus(err.message);
  }
}

async function logout() {
  try { await api("/api/logout", "POST"); } catch (_) {}
  localStorage.removeItem(tokenKey);
  token = "";
  currentConversationId = "";
  conversationStatuses.clear();
  memoryItems = [];
  authPanel.classList.remove("hidden");
  appPanel.classList.add("hidden");
  closeMemories();
}

async function deleteAccount() {
  const confirmed = confirm("确认注销账户吗？该操作会删除你的会话和记忆，且无法恢复。");
  if (!confirmed) return;

  try {
    await api("/api/account", "DELETE");
    await logout();
    setAuthMsg("账户已注销，相关数据已删除。");
  } catch (err) {
    setStatus(`注销失败：${err.message}`);
  }
}

document.getElementById("loginBtn").onclick = handleLogin;
document.getElementById("registerBtn").onclick = handleRegister;
sendBtn.onclick = sendMessage;
memoriesBtn.onclick = openMemories;
document.getElementById("newConvBtn").onclick = newConversation;
document.getElementById("renameBtn").onclick = renameConversation;
document.getElementById("deleteBtn").onclick = deleteConversation;
document.getElementById("logoutBtn").onclick = logout;
document.getElementById("deleteAccountBtn").onclick = deleteAccount;
memoryCloseBtn.onclick = closeMemories;
memoryRefreshBtn.onclick = refreshMemories;

memorySearchInput.addEventListener("input", applyMemoryFilter);

memoryListEl.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const memoryIdRaw = target.getAttribute("data-memory-id");
  if (!memoryIdRaw) return;
  const memoryId = Number(memoryIdRaw);
  if (!Number.isFinite(memoryId)) return;
  if (!confirm("确认删除这条记忆？")) return;
  await deleteMemoryById(memoryId);
});

memoryModalOverlay.addEventListener("click", (event) => {
  if (event.target === memoryModalOverlay) {
    closeMemories();
  }
});

messageEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
});

if (token) {
  enterApp();
}
