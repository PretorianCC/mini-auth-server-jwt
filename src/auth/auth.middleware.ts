import { type Request, type Response, type NextFunction } from 'express';
import { status_400, status_401 } from './auth.returnStatus';
import { ERR_JWT_EXPIRED, ERR_UNAUTHORIZED } from './auth.constants';
import { jwtVerify, errors } from 'jose';
import { jwtToken } from './auth.service';

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return status_401(res, ERR_UNAUTHORIZED);
  }
  const jwt = authHeader.slice(7);
  try {
    const { payload } = await jwtVerify(jwt, jwtToken);
    res.locals.payload = payload;
  } catch (err) {
    if ((err = errors.JWTExpired)) {
      return status_401(res, ERR_JWT_EXPIRED);
    }
    return status_401(res, ERR_UNAUTHORIZED);
  }

  next();
};
