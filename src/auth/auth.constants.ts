export const jWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET);
export const jWT_SECRET_REFRESH = new TextEncoder().encode(
  process.env.REFRESH_JWT_SECRET
);
export const HOST = process.env.HOST || 'localhost';

export const ERR_PASS_DONT_MATCH = 'Не совпадают пароли.';
export const ERR_USER_CREATION = 'Ошибка создания пользователя.';
export const ERR_UNAUTHORIZED = 'Не авторизован.';
export const ERR_JWT_EXPIRED = 'Срок действия токена истек.';
export const ERR_FIND_USER = 'Не найден пользователь.';
export const ERR_FIND_ADMIN = 'Не найден администратор.';
