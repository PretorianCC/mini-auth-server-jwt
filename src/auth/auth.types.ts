import { Auth } from '@/generated/prisma';

// Тип ответа регистрации пользователя
export type TAuthResponse = Omit<
  Auth,
  'passwordHash' | 'refreshToken' | 'createdAt' | 'updatedAt'
>;
