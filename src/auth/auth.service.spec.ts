import { describe, expect, it } from '@jest/globals';
import { createdUser } from './auth.service';
import { TNewUser } from './auth.dto';

describe('AuthService', () => {
  it('Создание пользователя', async () => {
    const newUser: TNewUser = {
      name: 'test',
      email: 'test@test.ru',
      password: '---',
      passwordOld: '---',
    };
    const user = await createdUser(newUser);
    expect(user).toHaveProperty('id');
    expect(user.name).toEqual('test');
  });
});
