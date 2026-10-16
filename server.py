from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, List, Optional
import bcrypt
import uuid
import time
import json
import random

app = FastAPI(title="Nexus Messenger")

# ============ STORAGE ============
users: Dict[str, dict] = {}
chats: Dict[str, dict] = {}
sessions: Dict[str, str] = {}       # token -> username (после 2FA)
pending_sessions: Dict[str, dict] = {}  # token -> {username, code}
sockets: Dict[str, WebSocket] = {}


# ============ MODELS ============
class RegisterData(BaseModel):
    username: str
    display: str
    password: str
    avatar: Optional[str] = ""


class LoginData(BaseModel):
    username: str
    password: str


class TwoFAData(BaseModel):
    token: str
    code: str


class AvatarData(BaseModel):
    username: str
    avatar: str


# ============ HELPERS ============
def safe_user(u: dict) -> dict:
    return {
        "username": u["username"],
        "display": u["display"],
        "avatar": u.get("avatar", "")
    }


def print_code(code: str, username: str):
    """Красивый вывод кода 2FA в терминал"""
    print()
    print("╔══════════════════════════════════════╗")
    print("║      🔐  ДВУХЭТАПНАЯ АУТЕНТИФИКАЦИЯ  ║")
    print("╠══════════════════════════════════════╣")
    print(f"║  Пользователь: @{username:<20} ║")
    print(f"║  Код:  {code:<30} ║")
    print("╚══════════════════════════════════════╝")
    print()


# ============ REGISTER ============
@app.post("/api/register")
async def register(data: RegisterData):
    username = data.username.strip().lower()
    display = data.display.strip() or username
    password = data.password

    if not username or not password:
        raise HTTPException(400, "Все поля обязательны")
    if len(username) < 3:
        raise HTTPException(400, "Имя минимум 3 символа")
    if len(password) < 4:
        raise HTTPException(400, "Пароль минимум 4 символа")
    if username in users:
        raise HTTPException(400, "Пользователь уже существует")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = {
        "id": str(uuid.uuid4()),
        "username": username,
        "display": display,
        "password": hashed,
        "avatar": data.avatar or ""
    }
    users[username] = user

    # 2FA
    code = f"{random.randint(0, 999999):06d}"
    token = str(uuid.uuid4())
    pending_sessions[token] = {"username": username, "code": code}
    print_code(code, username)

    return {"token": token, "user": safe_user(user), "need2fa": True}


# ============ LOGIN ============
@app.post("/api/login")
async def login(data: LoginData):
    username = data.username.strip().lower()
    user = users.get(username)
    if not user:
        raise HTTPException(400, "Неверный логин или пароль")

    ok = bcrypt.checkpw(data.password.encode(), user["password"].encode())
    if not ok:
        raise HTTPException(400, "Неверный логин или пароль")

    code = f"{random.randint(0, 999999):06d}"
    token = str(uuid.uuid4())
    pending_sessions[token] = {"username": username, "code": code}
    print_code(code, username)

    return {"token": token, "user": safe_user(user), "need2fa": True}


# ============ VERIFY 2FA ============
@app.post("/api/verify-2fa")
async def verify_2fa(data: TwoFAData):
    pending = pending_sessions.get(data.token)
    if not pending:
        raise HTTPException(400, "Сессия истекла, войдите заново")
    if pending["code"] != data.code.strip():
        raise HTTPException(400, "Неверный код")

    username = pending["username"]
    sessions[data.token] = username
    del pending_sessions[data.token]

    return {"ok": True, "user": safe_user(users[username])}


# ============ SEARCH USERS ============
@app.get("/api/search")
async def search_users(q: str = Query(""), me: str = Query("")):
    q = q.strip().lower().lstrip("@")
    me = me.lower()
    if not q:
        return []
    results = []
    for u in users.values():
        if u["username"] == me:
            continue
        if q in u["username"] or q in u["display"].lower():
            results.append(safe_user(u))
        if len(results) >= 10:
            break
    return results


# ============ GET USER ============
@app.get("/api/user/{username}")
async def get_user(username: str):
    u = users.get(username.lower())
    if not u:
        raise HTTPException(404, "Пользователь не найден")
    return safe_user(u)


# ============ UPDATE AVATAR ============
@app.post("/api/user/avatar")
async def update_avatar(data: AvatarData):
    u = users.get(data.username.lower())
    if not u:
        raise HTTPException(404, "Пользователь не найден")
    u["avatar"] = data.avatar
    return {"ok": True}


# ============ CHATS ============
@app.get("/api/chats")
async def get_chats(username: str = Query(...)):
    username = username.lower()
    my_chats = []
    for chat in chats.values():
        if username in chat["members"]:
            other_name = next((m for m in chat["members"] if m != username), None)
            other_user = users.get(other_name) if other_name else None
            last_msg = chat["messages"][-1] if chat["messages"] else None
            preview = ""
            if last_msg:
                preview = (last_msg.get("text")
                           or ("📷 Фото" if last_msg.get("image")
                               else ("📎 " + last_msg["file"]["name"] if last_msg.get("file")
                                     else "🎤 Голосовое")))
            my_chats.append({
                "id": chat["id"],
                "other": safe_user(other_user) if other_user else {
                    "username": other_name or "?", "display": other_name or "?", "avatar": ""
                },
                "lastMessage": preview,
                "lastTime": last_msg["time"] if last_msg else None
            })
    my_chats.sort(key=lambda c: c["lastTime"] or 0, reverse=True)
    return my_chats


@app.post("/api/chats")
async def create_chat(data: dict):
    from_u = data.get("from", "").lower()
    to_u = data.get("to", "").lower()

    if to_u not in users:
        raise HTTPException(404, "Пользователь не найден")
    if from_u == to_u:
        raise HTTPException(400, "Нельзя создать чат с собой")

    for chat in chats.values():
        if len(chat["members"]) == 2 and from_u in chat["members"] and to_u in chat["members"]:
            return {"id": chat["id"]}

    chat = {"id": str(uuid.uuid4()), "members": [from_u, to_u], "messages": []}
    chats[chat["id"]] = chat
    return {"id": chat["id"]}


@app.get("/api/messages/{chat_id}")
async def get_messages(chat_id: str):
    chat = chats.get(chat_id)
    if not chat:
        raise HTTPException(404, "Чат не найден")
    return chat["messages"]


# ============ WEBSOCKET ============
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    username = sessions.get(token)
    if not username:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    sockets[username] = websocket

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue

            mtype = msg.get("type")
            chat_id = msg.get("chatId")

            if mtype == "message":
                chat = chats.get(chat_id)
                if not chat or username not in chat["members"]:
                    continue

                text = (msg.get("text") or "").strip()
                image = msg.get("image")
                file_ = msg.get("file")
                voice = msg.get("voice")
                reply_to = msg.get("replyTo")

                if not (text or image or file_ or voice):
                    continue

                message = {
                    "id": str(uuid.uuid4()),
                    "from": username,
                    "time": int(time.time() * 1000),
                }
                if text: message["text"] = text
                if image: message["image"] = image
                if file_: message["file"] = file_
                if voice: message["voice"] = voice
                if reply_to:
                    # Найти оригинал
                    original = next((m for m in chat["messages"] if m["id"] == reply_to.get("id")), None)
                    if original:
                        orig_text = (original.get("text")
                                     or ("📷 Фото" if original.get("image")
                                         else ("📎 " + original["file"]["name"] if original.get("file")
                                               else "🎤 Голосовое")))
                        message["replyTo"] = {
                            "id": original["id"],
                            "from": original["from"],
                            "text": orig_text
                        }

                chat["messages"].append(message)
                await broadcast(chat, {"type": "message", "chatId": chat_id, "message": message})

            elif mtype == "edit":
                chat = chats.get(chat_id)
                if not chat or username not in chat["members"]:
                    continue
                msg_id = msg.get("messageId")
                new_text = (msg.get("text") or "").strip()
                for m in chat["messages"]:
                    if m["id"] == msg_id and m["from"] == username:
                        m["text"] = new_text
                        m["edited"] = True
                        await broadcast(chat, {
                            "type": "message_edited",
                            "chatId": chat_id,
                            "message": m
                        })
                        break

            elif mtype == "delete":
                chat = chats.get(chat_id)
                if not chat or username not in chat["members"]:
                    continue
                msg_id = msg.get("messageId")
                new_msgs = [m for m in chat["messages"] if not (m["id"] == msg_id and m["from"] == username)]
                if len(new_msgs) != len(chat["messages"]):
                    chat["messages"] = new_msgs
                    await broadcast(chat, {
                        "type": "message_deleted",
                        "chatId": chat_id,
                        "messageId": msg_id
                    })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print("WS error:", e)
    finally:
        if sockets.get(username) is websocket:
            del sockets[username]


async def broadcast(chat: dict, payload: dict):
    data = json.dumps(payload)
    for member in chat["members"]:
        sock = sockets.get(member)
        if sock:
            try:
                await sock.send_text(data)
            except Exception:
                pass


# ============ STATIC ============
@app.get("/")
async def index():
    return FileResponse("index.html")


app.mount("/", StaticFiles(directory=".", html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    print("✅ Сервер запущен: http://localhost:3000")
    print("📱 Открой в браузере и зарегистрируйся")
    print("🔐 Код 2FA будет появляться здесь, в терминале\n")
    uvicorn.run(app, host="0.0.0.0", port=3000)