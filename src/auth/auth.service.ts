import { prisma } from '../utils/database';
import { type Auth, Prisma } from '../generated/prisma';
import type { Tokens, AuthDto, CreateAuthDto, Token } from './auth.dto';
import { genSalt, hash, compare } from 'bcryptjs';
import type { TAuthResponse } from './auth.types';
import { jwtVerify, SignJWT } from 'jose';
import { Role } from '../generated/prisma';
import {
  HOST,
  jWT_SECRET_REFRESH,
  jWT_SECRET,
  TIMELIFE_TOKEN,
  TIMELIFE_TOKEN_REFRESH,
} from './auth.constants';

/**
 * @typedef {object} - payload токена.
 */
type Payload = {
  id: string;
};

const omitPrisma = { passwordHash: true };

/**
 * Создаёт новую учётную записи для авторизации.
 *
 * @param {CreateAuthDto} createdAuth - данные для создания пользователя.
 * @returns {Promise<TAuthResponse>} - созданная учетная запись.
 */
export const createdAuth = async (
  createdAuth: CreateAuthDto
): Promise<TAuthResponse> => {
  const salt = await genSalt(10);
  let passwordHash = await hash(createdAuth.password, salt);
  let auth: Prisma.AuthCreateInput = {
    name: createdAuth.name,
    email: createdAuth.email,
    passwordHash: passwordHash,
  };
  return prisma.auth.create({
    data: auth,
    omit: omitPrisma,
  });
};

/**
 * Поиск учетной записи по email.
 * (только для использования в локальном коде)
 *
 * @param {string} email - адрес электронной почты.
 * @returns {Promise<Auth | null>} - найденная учетная запись.
 */
export const findEmail = async (email: string): Promise<Auth | null> => {
  return prisma.auth.findUnique({
    where: {
      email,
    },
  });
};

/**
 * Поиск учетной записи по идентификатору.
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<TAuthResponse | null>} - найденная учетная запись.
 */
export const findId = async (id: string): Promise<TAuthResponse | null> => {
  return prisma.auth.findUnique({
    where: {
      id,
    },
    omit: omitPrisma,
  });
};

/**
 * Авторизация пользователя.
 *
 * @param {TAuth} login - логин и пароль.
 * @returns {Promise<Tokens | null>} - токены для авторизации.
 */
export const authToken = async (login: AuthDto): Promise<Tokens | null> => {
  const auth = await findEmail(login.login);
  if (!auth) {
    return Promise.resolve(null);
  }
  const isPassingPassword = await compare(login.password, auth.passwordHash);
  if (!isPassingPassword) {
    return Promise.resolve(null);
  }
  const payload: Payload = {
    id: auth.id,
  };

  const tokens = getTokens(payload);
  return Promise.resolve(tokens);
};

/**
 * Удалить учётную запись по идентификатору.
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<TAuthResponse>} - удалённая учетная запись.
 */
export const deleteAuth = async (id: string): Promise<TAuthResponse> => {
  return prisma.auth.delete({
    where: {
      id,
    },
    omit: omitPrisma,
  });
};

/**
 * Установить роль администратора.
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<TAuthResponse>} - учетная запись.
 */
export const setAdmin = async (id: string): Promise<TAuthResponse> => {
  return prisma.auth.update({
    where: {
      id,
    },
    omit: omitPrisma,
    data: {
      role: Role.ADMIN,
    },
  });
};

/**
 * Установить роль пользователя.
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<TAuthResponse>} - учетная запись.
 */
export const setUser = async (id: string): Promise<TAuthResponse> => {
  return prisma.auth.update({
    where: {
      id,
    },
    omit: omitPrisma,
    data: {
      role: Role.USER,
    },
  });
};

/**
 * Эта роль администратор? (только для сервера)
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<boolean>} - роль учетной записи администратор или нет.
 */
export const isAdmin = async (id: string): Promise<Boolean> => {
  let auth = null;
  try {
    auth = await findId(id);
  } catch {
    return Promise.resolve(false);
  }
  if (!auth) return Promise.resolve(false);
  return Promise.resolve(auth.role == Role.ADMIN);
};

/**
 * Эта роль пользователь? (только для сервера)
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<boolean>} - роль учетной записи пользователь или нет.
 */
export const isUser = async (id: string): Promise<Boolean> => {
  let auth = null;
  try {
    auth = await findId(id);
  } catch {
    return Promise.resolve(false);
  }
  if (!auth) return Promise.resolve(false);
  return Promise.resolve(auth.role == Role.USER);
};

/**
 * Создать токен.
 *
 * @param {object} payload - payload для токена.
 * @host {string} host - хост где выдан токен.
 * @param {string} time - время жизни токена.
 * @returns {Promise<string>} - токен.
 */
export const getToken = async (
  payload: Payload,
  host: string,
  time: string,
  jwtSecret: Uint8Array<ArrayBufferLike>
): Promise<string> => {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer(host)
    .setExpirationTime(time)
    .sign(jwtSecret);
};

/**
 * Создать токен и refrash токен.
 *
 * @param {object} payload - payload для токена.
 * @returns {Promise<Tokens | null>}
 */
export const getTokens = async (payload: Payload): Promise<Tokens | null> => {
  const token = await getToken(payload, HOST, TIMELIFE_TOKEN, jWT_SECRET);
  const refreshToken = await getToken(
    payload,
    HOST,
    TIMELIFE_TOKEN_REFRESH,
    jWT_SECRET_REFRESH
  );
  return Promise.resolve({
    token,
    refreshToken,
  });
};

/**
 * Выбрать учетные записи.
 *
 * @param {number} - skip - пропускает количество записей от начала.
 * @param {number} - take - получает количество записей.
 * @returns {Promise<TAuthResponse[]>} - учетные записи.
 */
export const several = async (
  skip: number,
  take: number
): Promise<TAuthResponse[]> => {
  return await prisma.auth.findMany({
    skip,
    take,
    omit: omitPrisma,
  });
};

/**
 * Получить payload из токена.
 *
 * @param {string} jwtToken - токен.
 * @returns {object} - payload токена.
 */
export const getPayload = async (
  jwtToken: Token,
  jwtSecret: Uint8Array<ArrayBufferLike>
): Promise<Payload> => {
  const { payload } = await jwtVerify(jwtToken, jwtSecret);
  return payload as Payload;
};
