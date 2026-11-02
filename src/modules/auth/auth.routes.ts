import { Router } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { validate, commonValidations } from '../../middleware/validation.middleware';
import { replayProtection } from '../../middleware/replay.middleware';
import { rateLimiter } from '../../middleware/rate-limit.middleware';
import { requireAuth } from '../../middleware/auth.middleware';
import { RegisterDto, LoginDto, ChangePasswordDto } from '../../validators/user.validator';

export function createAuthRouter(): Router {
  const router = Router();
  const authService = new AuthService(null as any);
  const authController = new AuthController(authService);

  router.post(
    '/register',
    rateLimiter.rateLimitMiddleware('sensitive'),
    replayProtection.replayProtectionMiddleware(),
    validate([
      commonValidations.username,
      commonValidations.email,
      commonValidations.password,
    ]),
    (req, res, next) => authController.register(req, res)
  );

  router.post(
    '/login',
    rateLimiter.rateLimitMiddleware('sensitive'),
    replayProtection.replayProtectionMiddleware(),
    validate([
      commonValidations.username,
    ]),
    (req, res, next) => authController.login(req, res)
  );

  router.post(
    '/refresh',
    rateLimiter.rateLimitMiddleware('sensitive'),
    (req, res, next) => authController.refresh(req, res)
  );

  router.post(
    '/logout',
    requireAuth(),
    (req, res, next) => authController.logout(req, res)
  );

  router.post(
    '/change-password',
    requireAuth(),
    rateLimiter.rateLimitMiddleware('sensitive'),
    validate([
      body('currentPassword').isString().notEmpty(),
      body('newPassword')
        .isLength({ min: 8, max: 128 })
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
    ]),
    (req, res, next) => authController.changePassword(req, res)
  );

  router.get(
    '/profile',
    requireAuth(),
    (req, res, next) => authController.getProfile(req, res)
  );

  router.get(
    '/profile/decrypted',
    requireAuth(),
    (req, res, next) => authController.getDecryptedProfile(req, res)
  );

  return router;
}

import { body } from 'express-validator';
