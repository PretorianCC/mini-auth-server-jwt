import { type Request, type Response, type NextFunction } from 'express';
import { status_401 } from './auth.returnStatus';
import {
  ERR_FIND_ADMIN,
  ERR_JWT_EXPIRED,
  ERR_UNAUTHORIZED,
} from './auth.constants';
import { errors } from 'jose';
import { getPayload, isAdmin } from './auth.service';

export const authMiddlewareUser = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { authorization } = req.headers;
  if (!authorization) {
    return status_401(res, ERR_UNAUTHORIZED);
  }
  const jwtToken = authorization.slice(7);
  try {
    res.locals.payload = await getPayload(jwtToken);
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
  const jwtToken = authorization.slice(7);
  try {
    res.locals.payload = await getPayload(jwtToken);
    if (!(await isAdmin(res.locals.payload.id))) {
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
