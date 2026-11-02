import { Router, Request, Response } from 'express';
import { DataService } from './data.service';
import { requireAuth, Role } from '../../middleware/auth.middleware';
import { body } from 'express-validator';
import { validate } from '../../middleware/validation.middleware';
import { logger } from '../../utils/logger';
import { AuthenticatedRequest } from '../../middleware/auth.middleware';

export function createDataRouter(): Router {
  const router = Router();
  const dataService = DataService.getInstance();

  router.post(
    '/encrypt',
    requireAuth(),
    validate([
      body('data').isString().notEmpty(),
      body('type').isIn(['phone', 'idCard', 'bankCard']),
    ]),
    (req: AuthenticatedRequest, res: Response) => {
      try {
        const { data, type } = req.body;
        const result = dataService.processAndStore(data, type);

        res.status(200).json({
          status: 'success',
          data: {
            encrypted: result.encrypted,
            masked: result.masked,
          },
        });
      } catch (error) {
        logger.error('Encrypt data error', { error: (error as Error).message });
        res.status(400).json({
          status: 'error',
          message: (error as Error).message,
          requestId: req.requestId,
        });
      }
    }
  );

  router.post(
    '/decrypt',
    requireAuth(),
    validate([
      body('encryptedData').isString().notEmpty(),
      body('type').isIn(['phone', 'idCard', 'bankCard']),
    ]),
    (req: AuthenticatedRequest, res: Response) => {
      try {
        const { encryptedData, type } = req.body;
        const decrypted = dataService.decryptSensitiveData(encryptedData, type);

        res.status(200).json({
          status: 'success',
          data: {
            decrypted,
          },
        });
      } catch (error) {
        logger.error('Decrypt data error', { error: (error as Error).message });
        res.status(400).json({
          status: 'error',
          message: (error as Error).message,
          requestId: req.requestId,
        });
      }
    }
  );

  router.post(
    '/mask',
    requireAuth(),
    validate([
      body('data').isString().notEmpty(),
      body('type').isIn(['phone', 'idCard', 'bankCard', 'email', 'name', 'address']),
    ]),
    (req: AuthenticatedRequest, res: Response) => {
      try {
        const { data, type } = req.body;
        const masked = dataService.maskSensitiveData(data, type);

        res.status(200).json({
          status: 'success',
          data: {
            masked,
          },
        });
      } catch (error) {
        logger.error('Mask data error', { error: (error as Error).message });
        res.status(400).json({
          status: 'error',
          message: (error as Error).message,
          requestId: req.requestId,
        });
      }
    }
  );

  return router;
}
