import { type Request, type Response, type NextFunction } from 'express';
import { status_401 } from './auth.returnStatus';
import {
  ERR_FIND_ADMIN,
  ERR_JWT_EXPIRED,
  ERR_UNAUTHORIZED,
  jwtSecret,
} from './auth.constants';
import { jwtVerify, errors } from 'jose';
import { isAdmin } from './auth.service';
import type { IdDto } from './auth.dto';

export const authMiddlewareUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { authorization } = req.headers;
  if (!authorization) {
    return status_401(res, ERR_UNAUTHORIZED);
  }
  const jwt = authorization.slice(7);
  try {
    const { payload } = await jwtVerify(jwt, jwtSecret);
    res.locals.payload = payload;
  } catch (err) {
    if ((err = errors.JWTExpired)) {
      return status_401(res, ERR_JWT_EXPIRED);
    }
    return status_401(res, ERR_UNAUTHORIZED);
  }

  next();
};

export const authMiddlewareAdmin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { authorization } = req.headers;
  if (!authorization) {
    return status_401(res, ERR_UNAUTHORIZED);
  }
  const jwt = authorization.slice(7);
  try {
    const { payload } = await jwtVerify(jwt, jwtSecret);
    const payloadAuth = payload as IdDto;
    res.locals.payload = payloadAuth;
    if (!(await isAdmin(payloadAuth.id))) {
      return status_401(res, ERR_FIND_ADMIN);
    }
  } catch (err) {
    if ((err = errors.JWTExpired)) {
      return status_401(res, ERR_JWT_EXPIRED);
    }
    return status_401(res, ERR_UNAUTHORIZED);
  }
  next();
};
