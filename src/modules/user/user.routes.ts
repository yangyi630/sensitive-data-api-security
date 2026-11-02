import { Router } from 'express';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { validate, commonValidations } from '../../middleware/validation.middleware';
import { requireAuth, Role } from '../../middleware/auth.middleware';
import { body, query } from 'express-validator';

export function createUserRouter(): Router {
  const router = Router();
  const userService = new UserService(null as any);
  const userController = new UserController(userService);

  router.get(
    '/',
    requireAuth(Role.ADMIN, Role.AUDITOR),
    validate([
      query('page').optional().isInt({ min: 1 }).toInt(),
      query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
      query('role').optional().isString(),
      query('search').optional().isString(),
    ]),
    (req, res) => userController.getAllUsers(req, res)
  );

  router.get(
    '/:id',
    requireAuth(),
    validate([
      commonValidations.idParam,
    ]),
    (req, res) => userController.getUserById(req, res)
  );

  router.get(
    '/:id/masked',
    requireAuth(),
    validate([
      commonValidations.idParam,
    ]),
    (req, res) => userController.getUserMaskedData(req, res)
  );

  router.put(
    '/profile',
    requireAuth(),
    validate([
      body('fullName').optional().isString().maxLength(100),
      body('phone').optional().isString(),
    ]),
    (req, res) => userController.updateProfile(req, res)
  );

  router.put(
    '/sensitive-data',
    requireAuth(),
    validate([
      body('phone').optional().isString(),
      body('idCard').optional().isString(),
      body('bankCard').optional().isString(),
    ]),
    (req, res) => userController.updateSensitiveData(req, res)
  );

  router.post(
    '/re-encrypt',
    requireAuth(Role.ADMIN),
    validate([
      body('userId').isUUID(),
      body('field').optional().isIn(['phone', 'idCard', 'bankCard']),
    ]),
    (req, res) => userController.reEncryptUserData(req, res)
  );

  router.delete(
    '/:id',
    requireAuth(Role.ADMIN),
    validate([
      commonValidations.idParam,
    ]),
    (req, res) => userController.deleteUser(req, res)
  );

  return router;
}
