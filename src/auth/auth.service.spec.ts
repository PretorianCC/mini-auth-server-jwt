import { expect, test, describe } from 'bun:test';
import { authToken, createdAuth, findEmail, findId } from './auth.service';
import type { AuthDto, CreateAuthDto } from './auth.dto';

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
    const user = await findId(id);
    expect(user).not.toBeNull();
    if (user) {
      expect(user).toHaveProperty('id');
      expect(user).toHaveProperty('createdAt');
      expect(user).toHaveProperty('updatedAt');
      expect(user).toHaveProperty('name', newAuth.name);
      expect(user).toHaveProperty('email', newAuth.email);
      expect(user).toHaveProperty('role', 'USER');
    }
  });

  test('Получить токены', async () => {
    const tokens = await authToken(login);
    expect(tokens).toHaveProperty('token');
    expect(tokens).toHaveProperty('refreshToken');
  });
});
