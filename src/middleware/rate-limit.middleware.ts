import Redis from 'ioredis';
import { Request, Response, NextFunction } from 'express';
import { getConfig } from '../../config';
import { logger } from '../../utils/logger';

export interface RateLimitInfo {
  ip: string;
  userId?: string;
  count: number;
  limit: number;
  remaining: number;
  resetTime: Date;
}

export class RateLimiter {
  private static instance: RateLimiter;
  private redis: Redis;
  private windowMs: number;
  private maxRequests: number;
  private sensitiveMax: number;

  private constructor() {
    const config = getConfig();
    this.redis = new Redis(config.redisUrl, { lazyConnect: true });
    this.windowMs = config.rateLimit.windowMs;
    this.maxRequests = config.rateLimit.maxRequests;
    this.sensitiveMax = config.rateLimit.sensitiveMax;
  }

  public static getInstance(): RateLimiter {
    if (!RateLimiter.instance) {
      RateLimiter.instance = new RateLimiter();
    }
    return RateLimiter.instance;
  }

  public async connect(): Promise<void> {
    await this.redis.connect();
  }

  public async disconnect(): Promise<void> {
    await this.redis.quit();
  }

  private getKey(identifier: string, type: 'general' | 'sensitive'): string {
    return `ratelimit:${type}:${identifier}`;
  }

  private async checkRateLimit(
    key: string,
    limit: number,
    windowMs: number
  ): Promise<{ count: number; remaining: number; resetTime: Date }> {
    const now = Date.now();
    const windowStart = now - windowMs;

    const luaScript = `
      local key = KEYS[1]
      local now = tonumber(ARGV[1])
      local window_start = tonumber(ARGV[2])
      local limit = tonumber(ARGV[3])
      local window_ms = tonumber(ARGV[4])

      redis.call('ZREMRANGEBYSCORE', key, 0, window_start)
      local current = redis.call('ZCARD', key)

      if current < limit then
        redis.call('ZADD', key, now, now .. ':' .. math.random())
        redis.call('PEXPIRE', key, window_ms)
      end

      local remaining = limit - redis.call('ZCARD', key)
      if remaining < 0 then remaining = 0 end

      return {redis.call('ZCARD', key), remaining}
    `;

    const result = await this.redis.eval(
      luaScript,
      1,
      key,
      now.toString(),
      windowStart.toString(),
      limit.toString(),
      windowMs.toString()
    ) as [number, number];

    const count = result[0];
    const remaining = Math.max(0, limit - count);
    const resetTime = new Date(now + windowMs);

    return { count, remaining, resetTime };
  }

  public async checkIpLimit(ip: string): Promise<RateLimitInfo> {
    const key = this.getKey(ip, 'general');
    const result = await this.checkRateLimit(key, this.maxRequests, this.windowMs);

    return {
      ip,
      count: result.count,
      limit: this.maxRequests,
      remaining: result.remaining,
      resetTime: result.resetTime,
    };
  }

  public async checkUserLimit(userId: string): Promise<RateLimitInfo> {
    const key = this.getKey(`user:${userId}`, 'general');
    const result = await this.checkRateLimit(key, this.maxRequests, this.windowMs);

    return {
      ip: 'unknown',
      userId,
      count: result.count,
      limit: this.maxRequests,
      remaining: result.remaining,
      resetTime: result.resetTime,
    };
  }

  public async checkSensitiveLimit(ip: string): Promise<RateLimitInfo> {
    const key = this.getKey(ip, 'sensitive');
    const result = await this.checkRateLimit(key, this.sensitiveMax, this.windowMs);

    return {
      ip,
      count: result.count,
      limit: this.sensitiveMax,
      remaining: result.remaining,
      resetTime: result.resetTime,
    };
  }

  public rateLimitMiddleware(type: 'general' | 'sensitive' = 'general') {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      const ip = req.ip || req.socket.remoteAddress || 'unknown';
      const userId = (req as any).user?.userId;

      try {
        let result: RateLimitInfo;

        if (type === 'sensitive') {
          result = await this.checkSensitiveLimit(ip);
        } else if (userId) {
          const [ipResult, userResult] = await Promise.all([
            this.checkIpLimit(ip),
            this.checkUserLimit(userId),
          ]);
          result = ipResult;
          result.userId = userId;
          result.count = Math.max(ipResult.count, userResult.count);
          result.limit = Math.min(ipResult.limit, userResult.limit);
          result.remaining = Math.min(ipResult.remaining, userResult.remaining);
        } else {
          result = await this.checkIpLimit(ip);
        }

        res.setHeader('X-RateLimit-Limit', result.limit);
        res.setHeader('X-RateLimit-Remaining', result.remaining);
        res.setHeader('X-RateLimit-Reset', result.resetTime.toISOString());

        if (result.remaining <= 0) {
          logger.warn('Rate limit exceeded', {
            ip,
            userId,
            type,
            count: result.count,
            limit: result.limit,
          });

          res.setHeader('Retry-After', Math.ceil(this.windowMs / 1000).toString());
          res.status(429).json({
            status: 'error',
            message: 'Too many requests, please try again later',
            requestId: (req as any).requestId,
          });
          return;
        }

        next();
      } catch (error) {
        logger.error('Rate limiter error', { error });
        next();
      }
    };
  }
}

export const rateLimiter = RateLimiter.getInstance();
