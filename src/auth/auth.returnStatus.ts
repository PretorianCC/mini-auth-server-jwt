import { type Response } from 'express';
import { logger } from '../utils/log';

export const status_200 = (res: Response, result: unknown) => {
  return res.status(200).json(result);
};

export const status_400 = (res: Response, message: string) => {
  logger.info(message);
  return res.status(400).json({ message });
};

export const status_401 = (res: Response, message: string) => {
  logger.info(message);
  return res.status(401).json({ message });
};
