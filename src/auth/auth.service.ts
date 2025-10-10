import { prisma } from '../utils/database';
import { type Auth, Prisma } from '../generated/prisma';
import type { Tokens, AuthDto, CreateAuthDto } from './auth.dto';
import { genSalt, hash, compare } from 'bcryptjs';
import type { TAuthResponse } from './auth.types';
import { SignJWT } from 'jose';

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
  const user = await findEmail(login.login);
  if (!user) {
    return user;
  }
  const isPassingPassword = await compare(login.password, user.passwordHash);
  if (!isPassingPassword) {
    return new Promise((resolve) => {
      resolve(null);
    });
  }
  const payload = {
    id: user.id,
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
 * @returns {Promise<TAuthResponse | null>} - удалённая учетная запись.
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
