import { Router } from 'express';
import { createdAuth, authToken } from './auth.service';
import { type Request, type Response } from 'express';
import { authMiddleware } from './auth.middleware';
import { authDto, createAuthDto, TAuth, TCreateAuth } from './auth.dto';
import {
  PassDontMatch,
  Unauthorized,
  UserCreationError,
} from './auth.constants';
import { status_200, status_400 } from './auth.returnStatus';

const router = Router();

// Регистрация пользователя.
//router.put("/auth/user", authMiddleware, (req: Request, res: Response) => {
router.put('/auth/user', async (req: Request, res: Response) => {
  const validation = createAuthDto.safeParse(req.body);
  if (!validation.success) {
    return status_400(res, JSON.parse(validation.error.message));
  }
  let newUser: TCreateAuth = req.body;
  if (newUser.password != newUser.passwordOld) {
    return status_400(res, PassDontMatch);
  }
  try {
    const result = await createdAuth(newUser);
    status_200(res, result);
  } catch {
    status_400(res, UserCreationError);
  }
});

// Авторизация по логину и паролю.
router.post('/auth/login', async (req: Request, res: Response) => {
  const validation = authDto.safeParse(req.body);
  if (!validation.success) {
    return status_400(res, JSON.parse(validation.error.message));
  }
  let auth: TAuth = req.body;
  const tokens = await authToken(auth);
  if (!tokens) {
    return status_400(res, Unauthorized);
  }
  res.json(tokens);
});

// Обновить токен пользователя.
router.post('/auth/refresh', (req: Request, res: Response) => {
  res.json({ message: 'Обновить токены пользователя.' });
});

// Удалить токены у пользователя.
router.post('/auth/logout', (req: Request, res: Response) => {
  res.json({ message: 'Удалить токены у пользователя.' });
});

// Удалить пользователя.
router.delete('/auth/user', (req: Request, res: Response) => {
  res.json({ message: 'Удалить пользователя.' });
});

// Получить пользователей.
router.get('/auth/users', (req: Request, res: Response) => {
  res.json({ message: 'Получить пользователей.' });
});

// Удалить всех не подтвержденных пользователей. (ни разу не авторизовался, удаляем).
router.delete('/auth/users', (req: Request, res: Response) => {
  res.json({ message: 'Удалить всех не подтвержденных пользователей.' });
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
