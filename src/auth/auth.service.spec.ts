import { expect, test, describe } from 'bun:test';
import {
  authToken,
  createdAuth,
  deleteAuth,
  findEmail,
  findId,
  getToken,
  isAdmin,
  isUser,
  setAdmin,
  setUser,
} from './auth.service';
import type { AuthDto, CreateAuthDto } from './auth.dto';
import { Role } from '../generated/prisma';
import { host, jwtSecret } from './auth.constants';

let id = '';
const newAuth: CreateAuthDto = {
  name: 'test',
  email: 'test@test.ru',
  password: '---',
  passwordOld: '---',
};
const login: AuthDto = {
  login: newAuth.email,
  password: newAuth.password,
};

describe('AuthService', () => {
  test('Новая учётная запись для авторизации', async () => {
    const user = await createdAuth(newAuth);
    id = user.id;
    expect(user).toHaveProperty('id');
    expect(user).toHaveProperty('createdAt');
    expect(user).toHaveProperty('updatedAt');
    expect(user.name).toEqual(newAuth.name);
    expect(user.email).toEqual(newAuth.email);
    expect(user.role).toEqual('USER');
  });

  test('Поиск учетной записи по email', async () => {
    const user = await findEmail('test@test.ru');
    if (!user) {
      expect(user).not.toBeNull();
    } else {
      expect(user).toHaveProperty('id');
      expect(user).toHaveProperty('createdAt');
      expect(user).toHaveProperty('updatedAt');
      expect(user.name).toEqual(newAuth.name);
      expect(user.email).toEqual(newAuth.email);
      expect(user.role).toEqual('USER');
    }
  });

  test('Поиск учетной записи по идентификатору', async () => {
    const auth = await findId(id);
    expect(auth).not.toBeNull();
    if (auth) {
      expect(auth).toHaveProperty('id');
      expect(auth).toHaveProperty('createdAt');
      expect(auth).toHaveProperty('updatedAt');
      expect(auth).toHaveProperty('name', newAuth.name);
      expect(auth).toHaveProperty('email', newAuth.email);
      expect(auth).toHaveProperty('role', Role.USER);
    }
  });

  test('Получить токен', async () => {
    const token = await getToken({ id }, host, '1h', jwtSecret);
    expect(token).toBeString();
  });

  test('Получить токены учётной записи', async () => {
    const tokens = await authToken(login);
    expect(tokens).toHaveProperty('token');
    expect(tokens).toHaveProperty('refreshToken');
  });

  test('Установить пользователем', async () => {
    const auth = await setUser(id);
    expect(auth).toHaveProperty('role', Role.USER);
  });

  test('Роль учётной записи - пользователь', async () => {
    const user = await isUser(id);
    expect(user).toBe(true);
  });

  test('Установить администратором', async () => {
    const auth = await setAdmin(id);
    expect(auth).toHaveProperty('role', Role.ADMIN);
  });

  test('Роль учётной записи - administrator', async () => {
    const user = await isAdmin(id);
    expect(user).toBe(true);
  });

  test('Удалить учётную запись по идентификатору', async () => {
    const auth = await deleteAuth(id);
    expect(auth).toHaveProperty('id');
    expect(auth).toHaveProperty('createdAt');
    expect(auth).toHaveProperty('updatedAt');
    expect(auth).toHaveProperty('name', newAuth.name);
    expect(auth).toHaveProperty('email', newAuth.email);
  });
});
