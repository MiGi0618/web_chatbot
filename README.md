# Web Chatbot (Windows test + Linux deploy)

## 功能
- 账号系统（注册 / 登录 / 退出）
- 按账号隔离会话
- 会话列表 + 重命名 + 删除（类似 ChatGPT）
- SQLite 落盘：用户、会话、消息、会话令牌

数据库默认路径：`web_chatbot/chat_history.db`

## 一、Windows 本地测试

### 1) 安装依赖
```powershell
python -m pip install flask openai werkzeug
```

### 2) 设置环境变量
```powershell
$env:OPENAI_API_KEY="你的key"
$env:OPENAI_BASE_URL="https://code.ppchat.vip/v1"
$env:OPENAI_MODEL="gpt-5.3-codex"
# 可选：
$env:CHATBOT_DB_PATH="E:\LearnForJob\web_chatbot\chat_history.db"
$env:SESSION_TTL_SECONDS="604800"
$env:MAX_CONTEXT_MESSAGES="24"
$env:MAX_USER_MEMORIES="30"
```

### 3) 启动
```powershell
python .\web_chatbot\app.py
```

浏览器访问：`http://127.0.0.1:8000`

## 二、Linux 服务器部署

### 1) 安装环境（Ubuntu 示例）
```bash
sudo apt update
sudo apt install -y python3 python3-venv
cd /opt/web_chatbot
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install flask openai werkzeug gunicorn
```

### 2) 设置环境变量
```bash
export OPENAI_API_KEY="你的key"
export OPENAI_BASE_URL="https://code.ppchat.vip/v1"
export OPENAI_MODEL="gpt-5.3-codex"
export CHATBOT_DB_PATH="/opt/web_chatbot/chat_history.db"
export SESSION_TTL_SECONDS="604800"
export MAX_CONTEXT_MESSAGES="24"
export MAX_USER_MEMORIES="30"
```

### 3) 运行（生产建议 gunicorn）
```bash
gunicorn -w 2 -b 0.0.0.0:8000 web_chatbot.app:app
```

## 三、主要接口
- `POST /api/register`
- `POST /api/login`
- `POST /api/logout`
- `GET /api/me`
- `GET /api/conversations`
- `POST /api/conversations`
- `GET /api/conversations/<id>/messages`
- `POST /api/chat` (非流式)
- `POST /api/chat/stream` (SSE 流式输出)
- `POST /api/conversations/<id>/rename`
- `DELETE /api/conversations/<id>`

## 四、上线建议
- 把 `OPENAI_API_KEY` 放在服务器环境变量，不要放前端
- 用 Nginx + HTTPS 反代
- 定期备份 `chat_history.db`
- 后续可加：验证码、限流、管理员封禁、密码找回

