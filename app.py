import functools
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Flask, Response, jsonify, render_template, request, stream_with_context
from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI
from werkzeug.security import check_password_hash, generate_password_hash

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.3-codex")
DEFAULT_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://code.ppchat.vip/v1")
DEFAULT_TIMEOUT = float(os.getenv("OPENAI_TIMEOUT", "60"))
SYSTEM_PROMPT = "You are a helpful, concise assistant."
DB_PATH = Path(os.getenv("CHATBOT_DB_PATH", Path(__file__).with_name("chat_history.db")))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", str(60 * 60 * 24 * 7)))
MAX_CONTEXT_MESSAGES = int(os.getenv("MAX_CONTEXT_MESSAGES", "24"))
MAX_USER_MEMORIES = int(os.getenv("MAX_USER_MEMORIES", "30"))

MEMORY_FIELD_LABELS = {
    "profession": "职业",
    "tech_stack": "技术栈",
    "platform": "平台环境",
    "language_preference": "回答语言偏好",
    "tech_preference": "技术方向偏好",
    "learning_goal": "学习目标",
    "long_term_project": "长期项目",
    "career_plan": "职业规划",
    "explicit_note": "用户显式记忆",
}

SINGLE_VALUE_MEMORY_KEYS = {
    "profession",
    "tech_stack",
    "platform",
    "language_preference",
    "tech_preference",
    "learning_goal",
    "long_term_project",
    "career_plan",
}

MEMORY_KEY_ALIASES = {
    "职业": "profession",
    "工作": "profession",
    "技术栈": "tech_stack",
    "平台": "platform",
    "系统": "platform",
    "语言": "language_preference",
    "中文": "language_preference",
    "英文": "language_preference",
    "偏好": "tech_preference",
    "方向": "tech_preference",
    "学习目标": "learning_goal",
    "目标": "learning_goal",
    "长期项目": "long_term_project",
    "项目": "long_term_project",
    "职业规划": "career_plan",
    "规划": "career_plan",
    "记忆": "explicit_note",
}

SENSITIVE_PATTERNS = [
    r"(?:身份证|银行卡|信用卡|密码|验证码|api\s*key|token|密钥)",
    r"\b1\d{10}\b",
    r"\b\d{15,19}\b",
]

TEMPORARY_HINTS = [
    "今天",
    "刚刚",
    "现在",
    "这会",
    "临时",
    "今晚",
    "明天",
    "周末",
    "这一小时",
]

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("web_chatbot")

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("Missing OPENAI_API_KEY. Set it before starting the server.")

client = OpenAI(
    api_key=api_key,
    base_url=DEFAULT_BASE_URL,
    timeout=DEFAULT_TIMEOUT,
    max_retries=int(os.getenv("OPENAI_MAX_RETRIES", "2")),
)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                source_conversation_id TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, key, value),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id, updated_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memories_user ON user_memories(user_id, updated_at)")


def cleanup_expired_sessions() -> None:
    now = int(time.time())
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))


def delete_user_account_data(user_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute(
            "DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = ?)",
            (user_id,),
        )
        conn.execute("DELETE FROM conversations WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM user_memories WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


def token_from_request() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def get_user_by_token(token: str) -> Optional[sqlite3.Row]:
    now = int(time.time())
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.username, s.token
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at >= ?
            """,
            (token, now),
        ).fetchone()
    return row


def auth_required(handler):
    @functools.wraps(handler)
    def wrapper(*args, **kwargs):
        token = token_from_request()
        if not token:
            return jsonify({"error": "Missing token"}), 401
        user = get_user_by_token(token)
        if not user:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.user = user  # type: ignore[attr-defined]
        return handler(*args, **kwargs)

    return wrapper


def derive_title(message: str) -> str:
    stripped = " ".join(message.split())
    if not stripped:
        return "新会话"
    return stripped[:30]


def create_conversation(user_id: int, title: str) -> str:
    conv_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            "INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)",
            (conv_id, user_id, title or "新会话"),
        )
        conn.execute(
            "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)",
            (conv_id, "system", SYSTEM_PROMPT),
        )
    return conv_id


def conversation_for_user(conversation_id: str, user_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, title FROM conversations WHERE id = ? AND user_id = ?",
            (conversation_id, user_id),
        ).fetchone()
    return row


def list_conversations(user_id: int) -> List[Dict[str, str]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, title, created_at, updated_at
            FROM conversations
            WHERE user_id = ?
            ORDER BY updated_at DESC, created_at DESC
            """,
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def load_messages(conversation_id: str) -> List[Dict[str, str]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT role, content FROM messages WHERE conversation_id = ? ORDER BY id ASC",
            (conversation_id,),
        ).fetchall()
    return [{"role": row["role"], "content": row["content"]} for row in rows]


def load_messages_for_context(conversation_id: str, max_messages: int) -> List[Dict[str, str]]:
    max_messages = max(2, max_messages)
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT role, content
            FROM messages
            WHERE conversation_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (conversation_id, max_messages),
        ).fetchall()

    if not rows:
        return [{"role": "system", "content": SYSTEM_PROMPT}]

    messages = [{"role": row["role"], "content": row["content"]} for row in reversed(rows)]

    has_system = any(msg["role"] == "system" for msg in messages)
    if not has_system:
        messages.insert(0, {"role": "system", "content": SYSTEM_PROMPT})

    return messages


def load_user_memories(user_id: int) -> List[Tuple[str, str]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT key, value
            FROM user_memories
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, MAX_USER_MEMORIES),
        ).fetchall()
    return [(row["key"], row["value"]) for row in rows]


def load_user_memory_items(user_id: int) -> List[Dict[str, object]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, key, value, updated_at
            FROM user_memories
            WHERE user_id = ?
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            """,
            (user_id, MAX_USER_MEMORIES),
        ).fetchall()

    return [
        {
            "id": int(row["id"]),
            "key": row["key"],
            "label": MEMORY_FIELD_LABELS.get(row["key"], row["key"]),
            "value": row["value"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def upsert_user_memory(user_id: int, key: str, value: str, source_conversation_id: str) -> None:
    if key in SINGLE_VALUE_MEMORY_KEYS:
        with get_db() as conn:
            conn.execute(
                "DELETE FROM user_memories WHERE user_id = ? AND key = ?",
                (user_id, key),
            )
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO user_memories (user_id, key, value, source_conversation_id)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, key, value)
            DO UPDATE SET updated_at = CURRENT_TIMESTAMP,
                          source_conversation_id = excluded.source_conversation_id
            """,
            (user_id, key, value, source_conversation_id),
        )


def delete_user_memory(user_id: int, key: str, value: Optional[str] = None) -> int:
    with get_db() as conn:
        if value:
            cur = conn.execute(
                "DELETE FROM user_memories WHERE user_id = ? AND key = ? AND value = ?",
                (user_id, key, value),
            )
        else:
            cur = conn.execute(
                "DELETE FROM user_memories WHERE user_id = ? AND key = ?",
                (user_id, key),
            )
    return int(cur.rowcount)


def is_sensitive_or_private(text: str) -> bool:
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    return False


def is_temporary_state(text: str) -> bool:
    return any(hint in text for hint in TEMPORARY_HINTS)


def normalize_memory_key(key_text: str) -> str:
    key_text = key_text.strip().lower()
    for alias, canonical in MEMORY_KEY_ALIASES.items():
        if alias in key_text:
            return canonical
    return "explicit_note"


def parse_explicit_memory_actions(text: str) -> Dict[str, List[Tuple[str, str]]]:
    actions: Dict[str, List[Tuple[str, str]]] = {"remember": [], "forget": [], "update": []}
    content = " ".join(text.split())

    remember_patterns = [
        r"(?:请)?记住(?:这个)?[:：]?(.{2,120})$",
        r"以后都这样[:：]?(.{2,120})$",
    ]
    update_patterns = [
        r"(?:把|将)?(?:我的|我)?(职业|技术栈|平台|系统|语言|偏好|学习目标|目标|长期项目|项目|职业规划|规划)(?:改成|改为|更新为|设为|换成|调整为)[:：]?(.{1,80})",
        r"(?:请)?更新(?:我的)?(职业|技术栈|平台|系统|语言|偏好|学习目标|目标|长期项目|项目|职业规划|规划)[:：]?(.{1,80})",
    ]
    forget_patterns = [
        r"(?:请)?把(.{1,50})忘掉",
        r"(?:请)?忘记(.{1,80})",
        r"(?:请)?删除(.{1,80})记忆",
        r"(?:请)?删掉(.{1,80})记忆",
    ]

    for pattern in remember_patterns:
        match = re.search(pattern, content)
        if not match:
            continue
        value = match.group(1).strip("。！!，, ")
        if value and not is_sensitive_or_private(value):
            actions["remember"].append(("explicit_note", value))

    for pattern in update_patterns:
        match = re.search(pattern, content)
        if not match:
            continue
        key_text = match.group(1).strip("。！!，, ")
        value = match.group(2).strip("。！!，, ")
        if value and not is_sensitive_or_private(value):
            actions["update"].append((normalize_memory_key(key_text), value))

    # Handle natural phrasing like "我不是主播了，我现在是程序员".
    profession_switch = re.search(
        r"(?:我不再是|我不是)\s*([^，。！？,.!?:：]{1,30})(?:了)?[，,;；\s]*(?:我现在是|现在是|我是)\s*([^，。！？,.!?:：]{1,30})",
        content,
    )
    if profession_switch:
        new_role = profession_switch.group(2).strip()
        if new_role and not is_sensitive_or_private(new_role):
            actions["update"].append(("profession", new_role))

    for pattern in forget_patterns:
        match = re.search(pattern, content)
        if not match:
            continue
        key_text = match.group(1).strip("。！!，, ")
        if key_text:
            actions["forget"].append((normalize_memory_key(key_text), key_text))

    return actions


def delete_user_memory_by_value(user_id: int, value_text: str) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM user_memories WHERE user_id = ? AND value LIKE ?",
            (user_id, f"%{value_text}%"),
        )
    return int(cur.rowcount)


def delete_user_memory_by_id(user_id: int, memory_id: int) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "DELETE FROM user_memories WHERE user_id = ? AND id = ?",
            (user_id, memory_id),
        )
    return int(cur.rowcount)


def extract_user_memories(text: str) -> List[Tuple[str, str]]:
    content = " ".join(text.split())
    if len(content) < 4:
        return []

    if is_sensitive_or_private(content):
        return []

    rules = [
        (
            "profession",
            r"(?:我是|我现在是|我的职业是)\s*([^，。！？,.!?:：]{2,30}(?:程序员|开发|工程师|主播|学生|教师|设计师|运营))",
        ),
        ("tech_stack", r"(?:我常用|我的技术栈是|我主要用)\s*([^。！？.!?]{2,60})"),
        ("platform", r"(?:我用|我的环境是|我主要在)\s*(Windows|Linux|macOS|Ubuntu|Debian|CentOS|Win11|Win10)"),
        ("language_preference", r"(?:请用|以后用|一直用)(中文|英文|中英文)"),
        ("tech_preference", r"(?:我偏好|我更偏向|我主要关注)\s*([^。！？.!?]{2,50})"),
        ("learning_goal", r"(?:我的学习目标是|我想学习|我正在学)\s*([^。！？.!?]{2,60})"),
        ("long_term_project", r"(?:我在做|我正在做|我的长期项目是)\s*([^。！？.!?]{3,80})"),
        ("career_plan", r"(?:我的职业规划是|我计划转向|我准备找)\s*([^。！？.!?]{3,80})"),
    ]

    memories: List[Tuple[str, str]] = []
    for key, pattern in rules:
        match = re.search(pattern, content)
        if not match:
            continue
        value = match.group(1).strip()
        if value and len(value) <= 80:
            memories.append((key, value))

    # Keep only latest distinct key entries from this turn.
    dedup: Dict[str, str] = {}
    for key, value in memories:
        dedup[key] = value
    return list(dedup.items())


def apply_memory_actions(user_id: int, conversation_id: str, text: str) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {"remembered": [], "forgotten": [], "updated": []}

    for key, value in extract_user_memories(text):
        upsert_user_memory(user_id, key, value, conversation_id)
        label = MEMORY_FIELD_LABELS.get(key, key)
        result["remembered"].append(f"{label}: {value}")

    actions = parse_explicit_memory_actions(text)
    for key, value in actions["remember"]:
        upsert_user_memory(user_id, key, value, conversation_id)
        label = MEMORY_FIELD_LABELS.get(key, key)
        result["remembered"].append(f"{label}: {value}")

    for key, value in actions["update"]:
        if not value:
            continue
        upsert_user_memory(user_id, key, value, conversation_id)
        label = MEMORY_FIELD_LABELS.get(key, key)
        result["updated"].append(f"{label}: {value}")

    for key, value in actions["forget"]:
        deleted = 0
        if key != "explicit_note":
            deleted = delete_user_memory(user_id, key, None)
        if deleted == 0 and value:
            deleted = delete_user_memory_by_value(user_id, value)
        if deleted == 0 and key == "explicit_note":
            deleted = delete_user_memory(user_id, key, None)
        if deleted > 0:
            label = MEMORY_FIELD_LABELS.get(key, key if key != "explicit_note" else value)
            result["forgotten"].append(label)

    return result


def build_context_messages(user_id: int, conversation_id: str) -> List[Dict[str, str]]:
    messages = load_messages_for_context(conversation_id, MAX_CONTEXT_MESSAGES)
    memories = load_user_memories(user_id)
    if not memories:
        return messages

    memory_lines = [f"- {MEMORY_FIELD_LABELS.get(key, key)}: {value}" for key, value in memories]
    memory_suffix = (
        "\n\n[提问时附加记忆，仅供回答参考]\n"
        + "\n".join(memory_lines)
        + "\n请结合以上记忆回答当前问题；若不相关可忽略。"
    )

    context_messages = [*messages]
    latest_user_index = -1
    for index in range(len(context_messages) - 1, -1, -1):
        if context_messages[index]["role"] == "user":
            latest_user_index = index
            break

    if latest_user_index == -1:
        context_messages.append(
            {
                "role": "user",
                "content": (
                    "[提问时附加记忆，仅供回答参考]\n"
                    + "\n".join(memory_lines)
                ),
            }
        )
        return context_messages

    latest_user = context_messages[latest_user_index]
    if "[提问时附加记忆，仅供回答参考]" not in latest_user["content"]:
        context_messages[latest_user_index] = {
            "role": "user",
            "content": f"{latest_user['content']}{memory_suffix}",
        }

    return context_messages


def insert_message(conversation_id: str, role: str, content: str) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO messages (conversation_id, role, content) VALUES (?, ?, ?)",
            (conversation_id, role, content),
        )
    return int(cur.lastrowid)


def delete_message(message_id: int) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))


def touch_conversation(conversation_id: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (conversation_id,),
        )


def maybe_update_title(conversation_id: str, current_title: str, user_message: str) -> None:
    if current_title != "新会话":
        return
    new_title = derive_title(user_message)
    with get_db() as conn:
        conn.execute("UPDATE conversations SET title = ? WHERE id = ?", (new_title, conversation_id))


def sse_event(event: str, payload: Dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


init_db()
cleanup_expired_sessions()


@app.get("/")
def index():
    return render_template("index.html", model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL)


@app.get("/api/health")
def health():
    try:
        client.models.list()
        return jsonify({"ok": True})
    except Exception as exc:
        logger.error("health_failed: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 503


@app.post("/api/register")
def register():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 chars"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 chars"}), 400

    with get_db() as conn:
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return jsonify({"error": "username already exists"}), 409
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(password)),
        )

    return jsonify({"ok": True})


@app.post("/api/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid username or password"}), 401

    token = secrets.token_urlsafe(32)
    expires_at = int(time.time()) + SESSION_TTL_SECONDS
    with get_db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, row["id"], expires_at),
        )

    return jsonify({"token": token, "username": row["username"], "expires_at": expires_at})


@app.post("/api/logout")
@auth_required
def logout():
    token = token_from_request()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return jsonify({"ok": True})


@app.delete("/api/account")
@auth_required
def delete_account():
    user = request.user  # type: ignore[attr-defined]
    delete_user_account_data(user["id"])
    return jsonify({"ok": True})


@app.get("/api/me")
@auth_required
def me():
    user = request.user  # type: ignore[attr-defined]
    return jsonify({"id": user["id"], "username": user["username"]})


@app.get("/api/conversations")
@auth_required
def conversations():
    user = request.user  # type: ignore[attr-defined]
    return jsonify({"items": list_conversations(user["id"])})


@app.get("/api/memories")
@auth_required
def memories():
    user = request.user  # type: ignore[attr-defined]
    items = load_user_memory_items(user["id"])
    return jsonify({"items": items})


@app.delete("/api/memories/<int:memory_id>")
@auth_required
def delete_memory(memory_id: int):
    user = request.user  # type: ignore[attr-defined]
    deleted = delete_user_memory_by_id(user["id"], memory_id)
    if deleted == 0:
        return jsonify({"error": "memory not found"}), 404
    return jsonify({"ok": True})


@app.post("/api/conversations")
@auth_required
def conversations_create():
    user = request.user  # type: ignore[attr-defined]
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip() or "新会话"
    conv_id = create_conversation(user["id"], title)
    return jsonify({"id": conv_id, "title": title})


@app.get("/api/conversations/<conversation_id>/messages")
@auth_required
def conversation_messages(conversation_id: str):
    user = request.user  # type: ignore[attr-defined]
    conv = conversation_for_user(conversation_id, user["id"])
    if not conv:
        return jsonify({"error": "conversation not found"}), 404
    return jsonify({"conversation_id": conversation_id, "title": conv["title"], "messages": load_messages(conversation_id)})


@app.post("/api/chat")
@auth_required
def chat():
    user = request.user  # type: ignore[attr-defined]
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    conversation_id = (payload.get("conversation_id") or "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    if conversation_id:
        conv = conversation_for_user(conversation_id, user["id"])
        if not conv:
            return jsonify({"error": "conversation not found"}), 404
    else:
        conversation_id = create_conversation(user["id"], derive_title(message))
        conv = conversation_for_user(conversation_id, user["id"])

    user_msg_id = insert_message(conversation_id, "user", message)
    memory_updates = apply_memory_actions(user["id"], conversation_id, message)
    messages = build_context_messages(user["id"], conversation_id)

    start = time.perf_counter()
    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=messages,
            temperature=0.7,
        )
        answer = response.choices[0].message.content or ""
        insert_message(conversation_id, "assistant", answer)
        maybe_update_title(conversation_id, conv["title"], message)  # type: ignore[index]
        touch_conversation(conversation_id)
        latency = round(time.perf_counter() - start, 2)
        logger.info("chat_ok user=%s conv=%s latency=%.2fs", user["id"], conversation_id, latency)
        return jsonify(
            {
                "conversation_id": conversation_id,
                "reply": answer,
                "latency": latency,
                "memory_updates": memory_updates,
                "conversations": list_conversations(user["id"]),
            }
        )

    except APITimeoutError:
        delete_message(user_msg_id)
        return jsonify({"error": "Request timed out. Check network/proxy and retry."}), 504

    except APIConnectionError:
        delete_message(user_msg_id)
        return jsonify({"error": "Cannot connect to API endpoint."}), 502

    except APIStatusError as exc:
        delete_message(user_msg_id)
        logger.error("api_status_error status=%s detail=%s", exc.status_code, exc)
        return jsonify({"error": f"Upstream API error: {exc.status_code}"}), 502

    except Exception as exc:
        delete_message(user_msg_id)
        logger.exception("unexpected_chat_error: %s", exc)
        return jsonify({"error": "Unexpected server error."}), 500


@app.post("/api/chat/stream")
@auth_required
def chat_stream():
    user = request.user  # type: ignore[attr-defined]
    payload = request.get_json(silent=True) or {}
    message = (payload.get("message") or "").strip()
    conversation_id = (payload.get("conversation_id") or "").strip()

    if not message:
        return jsonify({"error": "message is required"}), 400

    if conversation_id:
        conv = conversation_for_user(conversation_id, user["id"])
        if not conv:
            return jsonify({"error": "conversation not found"}), 404
    else:
        conversation_id = create_conversation(user["id"], derive_title(message))
        conv = conversation_for_user(conversation_id, user["id"])

    user_msg_id = insert_message(conversation_id, "user", message)
    memory_updates = apply_memory_actions(user["id"], conversation_id, message)
    messages = build_context_messages(user["id"], conversation_id)

    @stream_with_context
    def event_stream():
        start = time.perf_counter()
        assistant_parts: List[str] = []
        try:
            yield sse_event("meta", {"conversation_id": conversation_id})
            stream = client.chat.completions.create(
                model=DEFAULT_MODEL,
                messages=messages,
                temperature=0.7,
                stream=True,
            )

            for chunk in stream:
                choices = getattr(chunk, "choices", None) or []
                if not choices:
                    continue
                delta = getattr(choices[0], "delta", None)
                token = getattr(delta, "content", None) if delta else None
                if token:
                    assistant_parts.append(token)
                    yield sse_event("delta", {"text": token})

            answer = "".join(assistant_parts).strip() or "(空响应)"
            insert_message(conversation_id, "assistant", answer)
            maybe_update_title(conversation_id, conv["title"], message)  # type: ignore[index]
            touch_conversation(conversation_id)
            latency = round(time.perf_counter() - start, 2)
            logger.info("chat_stream_ok user=%s conv=%s latency=%.2fs", user["id"], conversation_id, latency)
            yield sse_event(
                "done",
                {
                    "conversation_id": conversation_id,
                    "latency": latency,
                    "memory_updates": memory_updates,
                },
            )

        except APITimeoutError:
            delete_message(user_msg_id)
            yield sse_event("error", {"message": "Request timed out. Check network/proxy and retry."})
        except APIConnectionError:
            delete_message(user_msg_id)
            yield sse_event("error", {"message": "Cannot connect to API endpoint."})
        except APIStatusError as exc:
            delete_message(user_msg_id)
            logger.error("api_status_error status=%s detail=%s", exc.status_code, exc)
            yield sse_event("error", {"message": f"Upstream API error: {exc.status_code}"})
        except Exception as exc:
            delete_message(user_msg_id)
            logger.exception("unexpected_chat_stream_error: %s", exc)
            yield sse_event("error", {"message": "Unexpected server error."})

    return Response(event_stream(), mimetype="text/event-stream")


@app.post("/api/conversations/<conversation_id>/rename")
@auth_required
def rename_conversation(conversation_id: str):
    user = request.user  # type: ignore[attr-defined]
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400

    conv = conversation_for_user(conversation_id, user["id"])
    if not conv:
        return jsonify({"error": "conversation not found"}), 404

    with get_db() as conn:
        conn.execute(
            "UPDATE conversations SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (title[:60], conversation_id),
        )
    return jsonify({"ok": True})


@app.delete("/api/conversations/<conversation_id>")
@auth_required
def delete_conversation(conversation_id: str):
    user = request.user  # type: ignore[attr-defined]
    conv = conversation_for_user(conversation_id, user["id"])
    if not conv:
        return jsonify({"error": "conversation not found"}), 404

    with get_db() as conn:
        conn.execute("DELETE FROM messages WHERE conversation_id = ?", (conversation_id,))
        conn.execute("DELETE FROM conversations WHERE id = ?", (conversation_id,))

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
