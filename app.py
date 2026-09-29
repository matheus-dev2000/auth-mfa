import os, uuid, datetime as dt
from functools import wraps
import jwt, pyotp
from flask import Flask, request, jsonify, g
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
SECRET = os.environ.get("JWT_SECRET", "troque-esta-chave-em-producao")
ph = PasswordHasher()  # Argon2id
ACCESS_MIN, REFRESH_DAYS = 15, 7

USERS = {}           # username -> {hash, totp_secret, mfa_enabled}
VALID_REFRESH = set()  # jti de refresh tokens válidos (rotação)

def make_token(username, kind):
    now = dt.datetime.now(dt.timezone.utc)
    exp = now + (dt.timedelta(minutes=ACCESS_MIN) if kind == "access"
                 else dt.timedelta(days=REFRESH_DAYS))
    jti = str(uuid.uuid4())
    if kind == "refresh":
        VALID_REFRESH.add(jti)
    return jwt.encode({"sub": username, "type": kind, "jti": jti,
                       "iat": now, "exp": exp}, SECRET, algorithm="HS256")

def decode(token, kind):
    data = jwt.decode(token, SECRET, algorithms=["HS256"])
    if data["type"] != kind:
        raise jwt.InvalidTokenError("tipo inválido")
    return data

def auth_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        try:
            token = request.headers.get("Authorization", "").split(" ")[1]
            g.user = decode(token, "access")["sub"]
        except Exception:
            return jsonify(error="não autorizado"), 401
        return f(*a, **kw)
    return wrapper

@app.post("/register")
def register():
    d = request.get_json()
    u, p = d.get("username"), d.get("password")
    if not u or not p or len(p) < 8:
        return jsonify(error="usuário e senha (mín. 8) obrigatórios"), 400
    if u in USERS:
        return jsonify(error="usuário já existe"), 409
    USERS[u] = {"hash": ph.hash(p), "totp_secret": None, "mfa_enabled": False}
    return jsonify(message="criado"), 201

@app.post("/login")
def login():
    d = request.get_json()
    user = USERS.get(d.get("username"))
    try:
        if not user:
            raise VerifyMismatchError()
        ph.verify(user["hash"], d.get("password", ""))
    except VerifyMismatchError:
        return jsonify(error="credenciais inválidas"), 401
    if user["mfa_enabled"]:
        otp = d.get("otp")
        if not otp:
            return jsonify(error="mfa_required"), 401
        if not pyotp.TOTP(user["totp_secret"]).verify(otp, valid_window=1):
            return jsonify(error="código MFA inválido"), 401
    u = d["username"]
    return jsonify(access_token=make_token(u, "access"),
                   refresh_token=make_token(u, "refresh"))

@app.post("/refresh")
def refresh():
    try:
        data = decode(request.get_json().get("refresh_token", ""), "refresh")
        if data["jti"] not in VALID_REFRESH:
            raise jwt.InvalidTokenError("reutilizado")
    except Exception:
        return jsonify(error="refresh token inválido"), 401
    VALID_REFRESH.discard(data["jti"])  # rotação: uso único
    u = data["sub"]
    return jsonify(access_token=make_token(u, "access"),
                   refresh_token=make_token(u, "refresh"))

@app.post("/mfa/setup")
@auth_required
def mfa_setup():
    secret = pyotp.random_base32()
    USERS[g.user]["totp_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=g.user, issuer_name="AuthMFA")
    return jsonify(secret=secret, otpauth_uri=uri)  # gere QR code com a URI

@app.post("/mfa/enable")
@auth_required
def mfa_enable():
    u = USERS[g.user]
    if not u["totp_secret"]:
        return jsonify(error="faça /mfa/setup primeiro"), 400
    if not pyotp.TOTP(u["totp_secret"]).verify(request.get_json().get("otp", ""), valid_window=1):
        return jsonify(error="código inválido"), 401
    u["mfa_enabled"] = True
    return jsonify(message="MFA ativado")

@app.get("/me")
@auth_required
def me():
    return jsonify(user=g.user, mfa=USERS[g.user]["mfa_enabled"])

if __name__ == "__main__":
    app.run(debug=False)
