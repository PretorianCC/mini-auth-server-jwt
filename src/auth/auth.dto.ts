import { z } from 'zod';

/** Данные для проверки создания учетной записи.
 *
 * @typedef {object} createAuthDto - cхема учётной записи.
 * @property {string} name - имя пользователя.
 * @property {string} email - электроннай почта.
 * @property {string} password - пароль.
 * @property {string} passwordOld - пароль для проверки.
 */
export const createAuthDto = z.object({
  name: z.string().min(2, 'Мало символов').max(100),
  email: z.email('Не электронная почта'),
  password: z.string().min(8, 'Мало символов').max(100),
  passwordOld: z.string().min(8, 'Мало символов').max(100),
});

/**
 * @typedef {object} - тип для создания учётной записи.
 */
export type CreateAuthDto = z.infer<typeof createAuthDto>;

/**
 * Данные для проверки авторизации пользователя.
 *
 * @typedef {object} authDto - cхема авторизации пользователя.
 * @property {string} login - логин пользователя (электронная почта).
 * @property {string} password - пароль.
 */
export const authDto = z.object({
  login: z.string(),
  password: z.string(),
});

/**
 * @typedef {object} - тип для авторизации пользователя.
 */
export type AuthDto = z.infer<typeof authDto>;

/**
 * Данные для проверки логина пользователя.
 *
 * @typedef {object} loginDto - cхема логина пользователя.
 * @property {string} login - логин пользователя (электронная почта).
 */
export const loginDto = authDto.omit({ password: true });

/**
 * @typedef {object} - тип для логина пользователя.
 */
export type LoginDto = z.infer<typeof loginDto>;

/**
 * @typedef {string} - тип jwt токен.
 */
export type Token = string;

/**
 * @typedef {object} - тип токены для авторизации.
 * @property {string} token - токен для авторизации.
 * @property {string} refreshToken - токен для обновления токенов для авторизации.
 */
export interface Tokens {
  token: Token;
  refreshToken: Token;
}

/**
 * @typedef {object} - тип идентификатор учетной записи.
 * @property {string} - id - идентификатор учетной записи.
 */
export const idDto = z.object({
  id: z.cuid('Не идентификатор учётной записи'),
});

/**
 * @typedef {object} - тип для логина пользователя.
 */
export type IdDto = z.infer<typeof idDto>;
