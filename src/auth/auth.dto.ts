import { z } from 'zod';

/** Данные для проверки создания учетной записи.
 *
 * @typedef {Object} createAuthDto - cхема учётной записи.
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
 * @type {TCreateAuth} - тип для создания учётной записи.
 */
export type TCreateAuth = z.infer<typeof createAuthDto>;

/**
 * Данные для проверки авторизации пользователя.
 *
 * @typedef {Object} authDto - cхема авторизации пользователя.
 * @property {string} login - логин пользователя (электронная почта).
 * @property {string} password - пароль.
 */
export const authDto = z.object({
  login: z.string(),
  password: z.string(),
});

/**
 * @type {TAuth} - тип для авторизации пользователя.
 */
export type TAuth = z.infer<typeof authDto>;

/**
 * Данные для проверки логина пользователя.
 *
 * @typedef {Object} loginDto - cхема логина пользователя.
 * @property {string} login - логин пользователя (электронная почта).
 */
export const loginDto = authDto.omit({ password: true });

/**
 * @type {TLogin} - тип для логина пользователя.
 */
export type TLogin = z.infer<typeof loginDto>;

/**
 * @type {ITokens} - тип токены для авторизации.
 */
export interface ITokens {
  token: string;
  refreshToken: string;
}