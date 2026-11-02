import { Request, Response, NextFunction } from 'express';
import { jwtService, JwtPayload } from '../../utils/jwt';
import { logger, logAudit } from '../../utils/logger';

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
  requestId?: string;
}

export enum Role {
  ADMIN = 'admin',
  USER = 'user',
  AUDITOR = 'auditor',
}

export const requireAuth = (allowedRoles?: Role[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logAudit({
        ip: req.ip || 'unknown',
        action: 'AUTH_FAILED',
        resource: req.path,
        result: 'failure',
        metadata: { reason: 'Missing or invalid authorization header' },
      });

      res.status(401).json({
        status: 'error',
        message: 'Authentication required',
        requestId: req.requestId,
      });
      return;
    }

    const token = authHeader.substring(7);

    try {
      const payload = jwtService.verifyAccessToken(token);
      req.user = payload;

      if (allowedRoles && allowedRoles.length > 0) {
        if (!allowedRoles.includes(payload.role as Role)) {
          logAudit({
            userId: payload.userId,
            ip: req.ip || 'unknown',
            action: 'ACCESS_DENIED',
            resource: req.path,
            result: 'failure',
            metadata: { requiredRoles: allowedRoles, userRole: payload.role },
          });

          res.status(403).json({
            status: 'error',
            message: 'Insufficient permissions',
            requestId: req.requestId,
          });
          return;
        }
      }

      next();
    } catch (error) {
      logAudit({
        ip: req.ip || 'unknown',
        action: 'AUTH_FAILED',
        resource: req.path,
        result: 'failure',
        metadata: { reason: (error as Error).message },
      });

      res.status(401).json({
        status: 'error',
        message: 'Invalid or expired token',
        requestId: req.requestId,
      });
    }
  };
};

export const requireRole = (...roles: Role[]) => {
  return requireAuth(roles);
};
