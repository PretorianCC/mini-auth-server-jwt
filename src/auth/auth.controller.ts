import { Router } from 'express';
import {
  createdAuth,
  authToken,
  findId,
  deleteAuth,
  setAdmin,
  setUser,
} from './auth.service';
import type { Request, Response } from 'express';
import { authMiddlewareAdmin, authMiddlewareUser } from './auth.middleware';
import { authDto, createAuthDto, idDto } from './auth.dto';
import type { AuthDto, CreateAuthDto, IdDto } from './auth.dto';
import {
  ERR_UNAUTHORIZED,
  ERR_PASS_DONT_MATCH,
  ERR_USER_CREATION,
  ERR_FIND_USER,
} from './auth.constants';
import { status_200, status_400 } from './auth.returnStatus';

const router = Router();

// Регистрация пользователя.
router.put('/auth/create', async (req: Request, res: Response) => {
  const newUser: CreateAuthDto = req.body;
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
  const auth: AuthDto = req.body;
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

// Получить текущую учётную запись.
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

// Удалить учетную запись.
router.delete(
  '/auth/user',
  authMiddlewareAdmin,
  async (req: Request, res: Response) => {
    const data: IdDto = req.body;
    const validation = idDto.safeParse(data);
    if (!validation.success) {
      return status_400(res, JSON.parse(validation.error.message));
    }
    try {
      const result = await deleteAuth(data.id);
      status_200(res, result);
    } catch {
      status_400(res, ERR_FIND_USER);
    }
  }
);

// Установить учетную запись администратором.
router.post(
  '/auth/set-admin',
  authMiddlewareAdmin,
  async (req: Request, res: Response) => {
    const data: IdDto = req.body;
    const validation = idDto.safeParse(data);
    if (!validation.success) {
      return status_400(res, JSON.parse(validation.error.message));
    }
    try {
      const result = await setAdmin(data.id);
      status_200(res, result);
    } catch {
      status_400(res, ERR_FIND_USER);
    }
  }
);

// Установить учетную запись пользователем.
router.post(
  '/auth/set-user',
  authMiddlewareAdmin,
  async (req: Request, res: Response) => {
    const data: IdDto = req.body;
    const validation = idDto.safeParse(data);
    if (!validation.success) {
      return status_400(res, JSON.parse(validation.error.message));
    }
    try {
      const result = await setUser(data.id);
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

// Получить пользователей.
router.get('/auth/several', (req: Request, res: Response) => {
  res.json({ message: 'Получить пользователей.' });
});

// Документация.
router.get('/', (req: Request, res: Response) => {
  res.send('REST Server AUTH');
});

export const auth = router;
