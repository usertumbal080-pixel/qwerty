from flask import Flask, request, jsonify
import asyncio, json, binascii, requests, aiohttp, urllib3, base64, time, hmac, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO, URLS_LIKE, FILES
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ── Konstanta ─────────────────────────────────────────────────────────────────
AES_KEY    = b'Yg&tc%DEuh6%Zc^8'
AES_IV     = b'6oyZDr22E3ychjM%'
MASTER_KEY = bytes.fromhex(
    "32656534343831396539623435393838343531343130363762323831363231383"
    "74643306435643761663964386637653030633165353437313562376431653"
    "3"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_token_expired(token: str, buffer_seconds: int = 300) -> bool:
    """Cek apakah JWT token sudah expired (dengan buffer 5 menit)."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get('exp', 0)
        return time.time() >= (exp - buffer_seconds)
    except Exception:
        return True  # anggap expired jika gagal parse


def refresh_token(uid: str, password: str) -> str | None:
    """
    Ambil token baru dari Garena menggunakan uid + password.
    Mengembalikan access_token baru atau None jika gagal.
    """
    url  = "https://100067.connect.garena.com/oauth/guest/token/grant"
    body = {
        "uid": uid, "password": password,
        "response_type": "token", "client_type": "2",
        "client_secret": MASTER_KEY, "client_id": "100067"
    }
    headers = {
        "Accept-Encoding": "gzip", "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
    }
    try:
        r = requests.post(url, headers=headers, data=body, timeout=15)
        return r.json().get('access_token')
    except Exception:
        return None


def load_tokens(server: str) -> list:
    """
    Muat token dari file JSON.
    Token yang expired akan dicoba di-refresh otomatis jika ada field uid+password.
    Token yang tidak bisa direfresh akan dilewati.
    """
    filepath = f"tokens/{FILES.get(server, 'token_bd.json')}"
    try:
        tokens = json.load(open(filepath))
    except Exception:
        return []

    valid   = []
    updated = False

    for entry in tokens:
        tok = entry.get('token', '')
        if not is_token_expired(tok):
            valid.append(entry)
            continue

        # Coba refresh jika ada uid + password tersimpan
        uid      = entry.get('uid') or entry.get('external_uid')
        password = entry.get('password')
        if uid and password:
            new_token = refresh_token(str(uid), password)
            if new_token:
                entry['token'] = new_token
                valid.append(entry)
                updated = True
                print(f"[TOKEN] Refreshed UID {uid}")
                continue

        print(f"[TOKEN] Skip expired token (no uid/pass to refresh)")

    # Simpan kembali jika ada yang diperbarui
    if updated:
        try:
            with open(filepath, 'w') as f:
                json.dump(tokens, f, indent=2)
        except Exception as e:
            print(f"[TOKEN] Gagal simpan token baru: {e}")

    return valid if valid else tokens  # fallback ke semua jika semua expired


def get_headers(token: str) -> dict:
    return {
        "User-Agent":      "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection":      "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization":   f"Bearer {token}",
        "Content-Type":    "application/x-www-form-urlencoded",
        "Expect":          "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA":            "v1 1",
        "ReleaseVersion":  "OB52",
    }


def encrypt_message(data: bytes) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return binascii.hexlify(cipher.encrypt(pad(data, AES.block_size))).decode()


def create_like(uid, region):
    m = like_pb2.like(); m.uid, m.region = int(uid), region
    return m.SerializeToString()


def create_uid(uid):
    m = uid_generator_pb2.uid_generator(); m.saturn_, m.garena = int(uid), 1
    return m.SerializeToString()


# ── Async send ────────────────────────────────────────────────────────────────

async def send(token, url, data):
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=bytes.fromhex(data),
                              headers=get_headers(token), ssl=False) as r:
                return await r.text() if r.status == 200 else None
    except Exception as e:
        print(f"[SEND] Error: {e}")
        return None


async def multi(uid, server, url):
    enc    = encrypt_message(create_like(uid, server))
    tokens = load_tokens(server)
    if not tokens:
        return []
    return await asyncio.gather(
        *[send(tokens[i % len(tokens)]['token'], url, enc) for i in range(105)]
    )


# ── Info player ───────────────────────────────────────────────────────────────

def get_info(enc, server, token):
    url = URLS_INFO.get(server, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")
    r   = requests.post(url, data=bytes.fromhex(enc),
                        headers=get_headers(token), verify=False, timeout=15)
    try:
        p = like_count_pb2.Info()
        p.ParseFromString(r.content)
        return p
    except DecodeError:
        return None


# ── Route /like ───────────────────────────────────────────────────────────────

@app.route("/like")
def like():
    uid    = request.args.get("uid")
    server = request.args.get("server", "").upper()

    if not uid or not server:
        return jsonify(error="UID and server required"), 400

    tokens = load_tokens(server)
    if not tokens:
        return jsonify(error=f"No valid tokens for server {server}"), 500

    enc          = encrypt_message(create_uid(uid))
    before, tok  = None, None

    for t in tokens[:10]:
        before = get_info(enc, server, t["token"])
        if before:
            tok = t["token"]
            break

    if not before:
        return jsonify(error="Player not found or all tokens expired"), 500

    before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

    asyncio.run(multi(uid, server, URLS_LIKE.get(server, "https://clientbp.ggblueshark.com/LikeProfile")))

    after      = json.loads(MessageToJson(get_info(enc, server, tok)))
    after_like = int(after.get('AccountInfo', {}).get('Likes', 0))

    return jsonify({
        "credits":      "great.thug4ff.com",
        "likes_added":  after_like - before_like,
        "likes_before": before_like,
        "likes_after":  after_like,
        "player":       after.get('AccountInfo', {}).get('PlayerNickname', ''),
        "uid":          after.get('AccountInfo', {}).get('UID', 0),
        "status":       1 if after_like - before_like else 2,
    })


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

# URL_ENDPOINTS = "http://127.0.0.1:5000/like?uid=13002831333&server=ME"
# credits: https://great.thug4ff.com/









    
#URL_ENPOINTS ="http://127.0.0.1:5000/like?uid=13002831333&server=me"
#credits : "https://great.thug4ff.com/"
