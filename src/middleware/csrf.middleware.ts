import { Request, Response, NextFunction } from 'express';
import { tokenService } from '../../services/token.service';
import { logger, logSecurity } from '../../utils/logger';
import { AuthenticatedRequest } from './auth.middleware';

export class CsrfProtection {
  private static instance: CsrfProtection;

  private constructor() {}

  public static getInstance(): CsrfProtection {
    if (!CsrfProtection.instance) {
      CsrfProtection.instance = new CsrfProtection();
    }
    return CsrfProtection.instance;
  }

  public csrfTokenGenerationMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      next();
    };
  }

  public csrfValidationMiddleware() {
    return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
      if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        next();
        return;
      }

      const csrfTokenFromHeader = req.headers['x-csrf-token'] as string;
      const csrfTokenFromCookie = req.cookies?.['csrf-token'];

      const ip = req.ip || 'unknown';

      if (!csrfTokenFromHeader) {
        logSecurity({
          userId: req.user?.userId,
          ip,
          action: 'CSRF_VALIDATION_FAILED',
          resource: req.path,
          result: 'failure',
          metadata: { reason: 'Missing CSRF token in header' },
        });

        res.status(403).json({
          status: 'error',
          message: 'CSRF token required',
          requestId: req.requestId,
        });
        return;
      }

      if (!req.user?.userId) {
        res.status(401).json({
          status: 'error',
          message: 'Authentication required',
          requestId: req.requestId,
        });
        return;
      }

      try {
        const isValid = await tokenService.validateCsrfToken(req.user.userId, csrfTokenFromHeader);

        if (!isValid) {
          logSecurity({
            userId: req.user?.userId,
            ip,
            action: 'CSRF_VALIDATION_FAILED',
            resource: req.path,
            result: 'failure',
            metadata: { reason: 'Invalid or expired CSRF token' },
          });

          res.status(403).json({
            status: 'error',
            message: 'Invalid CSRF token',
            requestId: req.requestId,
          });
          return;
        }

        next();
      } catch (error) {
        logger.error('CSRF validation error', { error });
        res.status(500).json({
          status: 'error',
          message: 'Internal server error',
          requestId: req.requestId,
        });
      }
    };
  }

  public extractCsrfToken(req: Request): string | undefined {
    return req.cookies?.['csrf-token'];
  }
}

export const csrfProtection = CsrfProtection.getInstance();
