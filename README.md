# Central de Autenticação Segura com MFA

API em Python (Flask) com hash de senha Argon2id, JWT de curta duração + refresh token e MFA via TOTP (Google Authenticator).

## Como rodar
```bash
pip install -r requirements.txt
export JWT_SECRET="uma-chave-longa-e-aleatoria"
python app.py
```

## Endpoints
| Método | Rota | Descrição |
|---|---|---|
| POST | /register | Cria usuário (senha ≥ 8) |
| POST | /login | Login (envia `otp` se MFA ativo) |
| POST | /refresh | Troca refresh token por novo par de tokens |
| POST | /mfa/setup | Gera segredo TOTP + URI otpauth (QR code) |
| POST | /mfa/enable | Confirma código e ativa MFA |
| GET | /me | Rota protegida |

## Arquitetura de segurança
- **Senhas:** Argon2id (argon2-cffi), com salt automático; nunca armazenadas em texto puro.
- **JWT:** access token de 15 min e refresh de 7 dias, assinados com HS256; claim `type` impede usar refresh como access.
- **Refresh com rotação:** cada refresh é de uso único (`jti` invalidado após uso), mitigando roubo/replay.
- **MFA TOTP (RFC 6238):** pyotp, janela de ±1 passo (30 s); ativado só após confirmar um código válido.
- **Login:** mensagem de erro genérica (evita enumeração de usuários).
- **Melhorias para produção:** banco de dados, HTTPS, rate limiting, segredo em variável de ambiente, códigos de backup do MFA.

## Testando (curl)
```bash
curl -X POST localhost:5000/register -H "Content-Type: application/json" -d '{"username":"ana","password":"senha12345"}'
curl -X POST localhost:5000/login -H "Content-Type: application/json" -d '{"username":"ana","password":"senha12345"}'
# use o access_token em /mfa/setup, escaneie a URI no Google Authenticator, depois /mfa/enable com o código
```
