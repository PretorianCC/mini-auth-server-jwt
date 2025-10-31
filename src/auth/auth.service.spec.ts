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
  several,
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
    const result = await findId(id);
    expect(result).not.toBeNull();
    if (result) {
      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('createdAt');
      expect(result).toHaveProperty('updatedAt');
      expect(result).toHaveProperty('name', newAuth.name);
      expect(result).toHaveProperty('email', newAuth.email);
      expect(result).toHaveProperty('role', Role.USER);
    }
  });

  test('Получить токен', async () => {
    const result = await getToken({ id }, host, '1h', jwtSecret);
    expect(result).toBeString();
  });

  test('Получить токены учётной записи', async () => {
    const result = await authToken(login);
    expect(result).toHaveProperty('token');
    expect(result).toHaveProperty('refreshToken');
  });

  test('Установить пользователем', async () => {
    const result = await setUser(id);
    expect(result).toHaveProperty('role', Role.USER);
  });

  test('Роль учётной записи - пользователь', async () => {
    const result = await isUser(id);
    expect(result).toBe(true);
  });

  test('Установить администратором', async () => {
    const result = await setAdmin(id);
    expect(result).toHaveProperty('role', Role.ADMIN);
  });

  test('Роль учётной записи - administrator', async () => {
    const result = await isAdmin(id);
    expect(result).toBe(true);
  });

  test('Выбрать несколько записей', async () => {
    const result = await several(0, 10);
    expect(result).toBeArray();
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
