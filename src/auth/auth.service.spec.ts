import { describe, expect, it } from '@jest/globals';
import { createdAuth } from './auth.service';
import type { CreateAuthDto } from './auth.dto';

describe('AuthService', () => {
  it('Создание пользователя', async () => {
    const newUser: CreateAuthDto = {
      name: 'test',
      email: 'test@test.ru',
      password: '---',
      passwordOld: '---',
    };
    const user = await createdAuth(newUser);
    expect(user).toHaveProperty('id');
    expect(user.name).toEqual('test');
  });
});
