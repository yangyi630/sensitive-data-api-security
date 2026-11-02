import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

export interface RequestWithId extends Request {
  requestId: string;
  startTime: number;
}

export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = (req.headers['x-request-id'] as string) || uuidv4();
  (req as RequestWithId).requestId = requestId;
  (req as RequestWithId).startTime = Date.now();

  res.setHeader('X-Request-Id', requestId);
  next();
}

export function requestLoggingMiddleware(req: Request, res: Response, next: NextFunction): void {
  const { requestId, startTime } = req as RequestWithId;
  const originalEnd = res.end;

  res.end = function (this: Response, ...args: any[]): ReturnType<typeof originalEnd> {
    const duration = Date.now() - startTime;

    logger.info('HTTP Request', {
      requestId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });

    return originalEnd.apply(this, args);
  };

  next();
}

export function errorHandlerMiddleware(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const { requestId } = req as RequestWithId;

  logger.error('Unhandled error', {
    requestId,
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
  });

  res.status(500).json({
    status: 'error',
    message: 'Internal server error',
    requestId,
  });
}
