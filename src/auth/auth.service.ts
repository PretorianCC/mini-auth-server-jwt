import { prisma } from '../utils/database';
import { type Auth, Prisma } from '../generated/prisma';
import type { Tokens, AuthDto, CreateAuthDto } from './auth.dto';
import { genSalt, hash, compare } from 'bcryptjs';
import type { TAuthResponse } from './auth.types';
import { SignJWT } from 'jose';
import { Role } from '../generated/prisma';

export const jwtToken = new TextEncoder().encode(process.env.JWT_SECRET);
const jwtRefreshToken = new TextEncoder().encode(process.env.JWT_SECRET);
const host = process.env.HOST || 'localhost';

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
    omit: {
      passwordHash: true,
    },
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
    omit: {
      passwordHash: true,
    },
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
    return auth;
  }
  const isPassingPassword = await compare(login.password, auth.passwordHash);
  if (!isPassingPassword) {
    return new Promise((resolve) => {
      resolve(null);
    });
  }
  const payload = {
    id: auth.id,
  };

  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer(host)
    .setExpirationTime('1h')
    .sign(jwtToken);

  const refreshToken = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer(host)
    .setExpirationTime('4w')
    .sign(jwtRefreshToken);

  return new Promise((resolve) =>
    resolve({
      token,
      refreshToken,
    })
  );
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
    omit: {
      passwordHash: true,
    },
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
    omit: {
      passwordHash: true,
    },
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
    omit: {
      passwordHash: true,
    },
    data: {
      role: Role.USER,
    },
  });
};

/**
 * Эта роль администратор?
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<boolean>} - роль учетной записи администратор или нет.
 */
export const isAdmin = async (id: string): Promise<Boolean> => {
  let auth = null;
  try {
    auth = await findId(id);
  } catch {
    new Promise((resolve) => {
      resolve(false);
    });
  }
  if (!auth) return false;
  return new Promise((resolve) => {
    resolve(auth.role == Role.ADMIN);
  });
};

/**
 * Эта роль пользователь?
 *
 * @param {number} id - идентификатор учетной записи.
 * @returns {Promise<boolean>} - роль учетной записи пользователь или нет.
 */
export const isUser = async (id: string): Promise<Boolean> => {
  let auth = null;
  try {
    auth = await findId(id);
  } catch {
    new Promise((resolve) => {
      resolve(false);
    });
  }
  if (!auth) return false;
  return new Promise((resolve) => {
    resolve(auth.role == Role.USER);
  });
};
