import express from 'express';
import { type Request, type Response, type NextFunction } from 'express';
import dotenv from 'dotenv';
import { auth } from './auth/auth.controller';
import { PrismaClient } from './generated/prisma';
import { logger } from './utils/log';
import helmet from 'helmet';
//import compression from 'compression';

dotenv.config();
const port = process.env.PORT || 3000;
const app = express();
export const prisma = new PrismaClient();

async function main() {
  app.use(helmet());
  //app.use(compression);
  app.use(express.json());
  const router = app.router;

  app.use('/api', auth);

  app.all('*splat', (req: Request, res: Response) => {
    res.status(404).json({ message: 'Not Found' });
  });

  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    logger.error(err.stack);
    res.status(500).send('Internal Server Error');
  });

  app.listen(port, () => {
    logger.info(`App listening on port ${port}`);
  });
}

main()
  .then(async () => {
    await prisma.$connect();
  })
  .catch(async (e) => {
    logger.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
