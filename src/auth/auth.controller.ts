import { Router } from 'express';
import { createdAuth, authToken, findId } from './auth.service';
import type { Request, Response } from 'express';
import { authMiddlewareUser } from './auth.middleware';
import { authDto, createAuthDto } from './auth.dto';
import type { AuthDto, CreateAuthDto } from './auth.dto';
import {
  ERR_UNAUTHORIZED,
  ERR_PASS_DONT_MATCH,
  ERR_USER_CREATION,
  ERR_FIND_USER,
} from './auth.constants';
import { status_200, status_400 } from './auth.returnStatus';

const router = Router();

// Регистрация пользователя.
router.put('/auth/user', async (req: Request, res: Response) => {
  let newUser: CreateAuthDto = req.body;
  const validation = createAuthDto.safeParse(newUser);
  if (!validation.success) {
    return status_400(res, JSON.parse(validation.error.message));
  }
  if (newUser.password != newUser.passwordOld) {
    return status_400(res, ERR_PASS_DONT_MATCH);
  }
  try {
    const result = await createdAuth(newUser);
    status_200(res, result);
  } catch {
    status_400(res, ERR_USER_CREATION);
  }
});

// Авторизация по логину и паролю, получить токены.
router.post('/auth/login', async (req: Request, res: Response) => {
  let auth: AuthDto = req.body;
  const validation = authDto.safeParse(auth);
  if (!validation.success) {
    return status_400(res, JSON.parse(validation.error.message));
  }
  try {
    const result = await authToken(auth);
    status_200(res, result);
  } catch {
    status_400(res, ERR_UNAUTHORIZED);
  }
});

// Получить пользователя.
router.get(
  '/auth/user',
  authMiddlewareUser,
  async (req: Request, res: Response) => {
    const payload = res.locals?.payload;
    try {
      const result = await findId(payload.id);
      status_200(res, result);
    } catch {
      status_400(res, ERR_FIND_USER);
    }
  }
);

// Обновить токен пользователя.
router.post('/auth/refresh', (req: Request, res: Response) => {
  res.json({ message: 'Обновить токены пользователя.' });
});

// Удалить пользователя.
router.delete('/auth/user', (req: Request, res: Response) => {
  res.json({ message: 'Удалить пользователя.' });
});

// Получить пользователей.
router.get('/auth/users', (req: Request, res: Response) => {
  res.json({ message: 'Получить пользователей.' });
});

// Установить/удалить пользователя из администратора (кроме последнего).
router.post('/auth/admin', (req: Request, res: Response) => {
  res.json({ message: 'Установить/удалить пользователя из администратора.' });
});

// Документация.
router.get('/', (req: Request, res: Response) => {
  res.send('REST Server AUTH');
});

export const auth = router;
