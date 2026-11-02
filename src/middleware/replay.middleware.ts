import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import { getConfig } from '../../config';
import { logger, logSecurity } from '../../utils/logger';

export interface ReplayCheckResult {
  valid: boolean;
  reason?: string;
}

export class ReplayProtection {
  private static instance: ReplayProtection;
  private redis: Redis;
  private nonceExpiresSeconds: number;
  private timestampToleranceMs: number;

  private constructor() {
    const config = getConfig();
    this.redis = new Redis(config.redisUrl, { lazyConnect: true });
    this.nonceExpiresSeconds = config.security.nonceExpiresSeconds;
    this.timestampToleranceMs = config.security.timestampToleranceMs;
  }

  public static getInstance(): ReplayProtection {
    if (!ReplayProtection.instance) {
      ReplayProtection.instance = new ReplayProtection();
    }
    return ReplayProtection.instance;
  }

  public async connect(): Promise<void> {
    await this.redis.connect();
  }

  public async disconnect(): Promise<void> {
    await this.redis.quit();
  }

  public async checkReplay(nonce: string, timestamp: number, ip: string): Promise<ReplayCheckResult> {
    const now = Date.now();

    if (Math.abs(now - timestamp) > this.timestampToleranceMs) {
      logSecurity({
        ip,
        action: 'REPLAY_CHECK_FAILED',
        resource: 'anti_replay',
        result: 'failure',
        metadata: { reason: 'Timestamp out of tolerance', timestamp, serverTime: now },
      });

      return {
        valid: false,
        reason: 'Request timestamp is outside acceptable range',
      };
    }

    const nonceKey = `nonce:${nonce}`;
    const luaScript = `
      local key = KEYS[1]
      local exists = redis.call('EXISTS', key)
      if exists == 1 then
        return 0
      end
      redis.call('SETEX', key, tonumber(ARGV[1]), '1')
      return 1
    `;

    try {
      const result = await this.redis.eval(
        luaScript,
        1,
        nonceKey,
        this.nonceExpiresSeconds.toString()
      ) as number;

      if (result === 0) {
        logSecurity({
          ip,
          action: 'REPLAY_ATTACK_DETECTED',
          resource: 'anti_replay',
          result: 'failure',
          metadata: { nonce, timestamp },
        });

        return {
          valid: false,
          reason: 'Nonce has already been used',
        };
      }

      return { valid: true };
    } catch (error) {
      logger.error('Replay check Redis error', { error, nonce, timestamp });
      return {
        valid: false,
        reason: 'Unable to verify request',
      };
    }
  }

  public replayProtectionMiddleware() {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const nonce = req.headers['x-nonce'] as string;
      const timestampHeader = req.headers['x-timestamp'] as string;
      const ip = req.ip || req.socket.remoteAddress || 'unknown';

      if (!nonce || !timestampHeader) {
        logSecurity({
          ip,
          action: 'REPLAY_CHECK_FAILED',
          resource: 'anti_replay',
          result: 'failure',
          metadata: { reason: 'Missing nonce or timestamp headers' },
        });

        res.status(400).json({
          status: 'error',
          message: 'Missing required security headers (X-Nonce, X-Timestamp)',
          requestId: (req as any).requestId,
        });
        return;
      }

      const timestamp = parseInt(timestampHeader, 10);
      if (isNaN(timestamp)) {
        res.status(400).json({
          status: 'error',
          message: 'Invalid timestamp format',
          requestId: (req as any).requestId,
        });
        return;
      }

      const result = await this.checkReplay(nonce, timestamp, ip);

      if (!result.valid) {
        res.status(400).json({
          status: 'error',
          message: result.reason,
          requestId: (req as any).requestId,
        });
        return;
      }

      next();
    };
  }
}

export const replayProtection = ReplayProtection.getInstance();
