import { type Request, type Response, type NextFunction } from 'express';
import { status_401 } from './auth.returnStatus';
import { Unauthorized } from './auth.constants';

export const authMiddleware = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return status_401(res, Unauthorized);
  }
  next();
};
