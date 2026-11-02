import 'reflect-metadata';
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { getConfig } from './config';
import { getSecurityHeadersMiddleware, securityHeadersMiddleware } from './middleware/headers.middleware';
import { requestIdMiddleware, requestLoggingMiddleware, errorHandlerMiddleware } from './middleware/common.middleware';
import { rateLimiter } from './middleware/rate-limit.middleware';
import { replayProtection } from './middleware/replay.middleware';
import { createAuthRouter } from './modules/auth/auth.routes';
import { createUserRouter } from './modules/user/user.routes';
import { createDataRouter } from './modules/data/data.routes';
import { logger } from './utils/logger';
import swaggerUi from 'swagger-ui-express';
import { swaggerSpec } from './config/swagger';
import { AppDataSource } from './config/typeorm';

const config = getConfig();

async function bootstrap(): Promise<void> {
  try {
    await AppDataSource.initialize();
    logger.info('Database connection established');

    await AppDataSource.runMigrations();
    logger.info('Database migrations completed');
  } catch (error) {
    logger.warn('Database connection failed, running in standalone mode', { error });
  }

  try {
    await rateLimiter.connect();
    logger.info('Redis connection established');
  } catch (error) {
    logger.warn('Redis connection failed, rate limiting may not work', { error });
  }

  try {
    await replayProtection.connect();
  } catch (error) {
    logger.warn('Replay protection Redis connection failed', { error });
  }

  const app = express();

  app.use(compression());

  app.use(cookieParser());

  app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
      next();
    } else if (config.nodeEnv === 'production') {
      res.redirect(301, `https://${req.hostname}${req.url}`);
    } else {
      next();
    }
  });

  app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  }));

  app.use(getSecurityHeadersMiddleware());

  app.use(cors({
    origin: (origin, callback) => {
      if (!origin || config.cors.origins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn('CORS blocked request from unauthorized origin', { origin });
        callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Nonce',
      'X-Timestamp',
      'X-CSRF-Token',
      'X-Request-Id',
    ],
    exposedHeaders: [
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
      'X-Request-Id',
    ],
    credentials: true,
    maxAge: 86400,
  }));

  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: true, limit: '10kb' }));

  app.use(requestIdMiddleware);
  app.use(requestLoggingMiddleware);

  app.get('/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    });
  });

  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'Secure API Documentation',
  }));

  app.use('/api/auth', replayProtection.replayProtectionMiddleware(), rateLimiter.rateLimitMiddleware(), createAuthRouter());
  app.use('/api/users', replayProtection.replayProtectionMiddleware(), rateLimiter.rateLimitMiddleware(), createUserRouter());
  app.use('/api/data', replayProtection.replayProtectionMiddleware(), rateLimiter.rateLimitMiddleware(), createDataRouter());

  app.use(errorHandlerMiddleware);

  app.use((req, res) => {
    res.status(404).json({
      status: 'error',
      message: 'Endpoint not found',
      requestId: (req as any).requestId,
    });
  });

  const server = app.listen(config.port, () => {
    logger.info(`Server started on port ${config.port}`, {
      environment: config.nodeEnv,
      port: config.port,
    });
  });

  const gracefulShutdown = async (signal: string): Promise<void> => {
    logger.info(`${signal} received, shutting down gracefully`);

    server.close(async () => {
      logger.info('HTTP server closed');

      try {
        await rateLimiter.disconnect();
        await replayProtection.disconnect();
        await AppDataSource.destroy();
        logger.info('All connections closed');
        process.exit(0);
      } catch (error) {
        logger.error('Error during shutdown', { error });
        process.exit(1);
      }
    });

    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

bootstrap().catch((error) => {
  logger.error('Failed to start server', { error });
  process.exit(1);
});
