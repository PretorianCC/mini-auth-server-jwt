import { prisma } from '../utils/database';
import { type Auth, Prisma } from '../generated/prisma';
import type { Tokens, AuthDto, CreateAuthDto } from './auth.dto';
import { genSalt, hash, compare } from 'bcryptjs';
import type { TAuthResponse } from './auth.types';
import { SignJWT, jwtVerify } from 'jose';

const jwtToken = new TextEncoder().encode(process.env.JWT_SECRET);
const jwtRefreshToken = new TextEncoder().encode(process.env.JWT_SECRET);
const host = process.env.HOST || 'localhost';

/**
 * Создаёт новую учётную записб для авторизации.
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
      createdAt: true,
      updatedAt: true,
    },
  });
};

/**
 * Поиск учетной записи по email.
 *
 * @param {string} email - адрес электронной почты.
 * @returns {Promise<Auth | null>} найденная учетная запись.
 */
export const findEmail = async (email: string): Promise<Auth | null> => {
  return prisma.auth.findUnique({
    where: {
      email,
    },
  });
};

/**
 * Авторизация пользователя.
 *
 * @param {TAuth} login - логин и пароль.
 *
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
    email: user.email,
    role: user.role,
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

// import { SignJWT, jwtVerify } from 'jose';

// const secret = new TextEncoder().encode(process.env.JWT_SECRET);

// // Create token
// const token = await new SignJWT({ userId: 123 })
//   .setProtectedHeader({ alg: 'HS256' })
//   .setExpirationTime('1h')
//   .sign(secret);

// // Verify token
// try {
//   const { payload } = await jwtVerify(token, secret);
//   console.log(payload.userId);
// } catch (err) {
//   console.error('Invalid token');
// }
