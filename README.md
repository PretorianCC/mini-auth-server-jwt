# mini-auth-server-jwt

### Rest cервервис для авторизации пользователей.

Служит для создания и обновления JWT токенов для авторизации на других сервисах.

_.env_

```env
NODE_ENV=development
HOST="..."
PORT=3000
DATABASE_URL="postgres://пользователь:пароль@сервер:5432/БД?schema=public"
JWT_SECRET="..."
REFRESH_JWT_SECRET="..."
```
