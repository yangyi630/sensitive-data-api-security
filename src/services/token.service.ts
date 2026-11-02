import Redis from 'ioredis';
import { getConfig } from '../config';
import { jwtService, RefreshTokenPayload } from '../utils/jwt';

export class TokenService {
  private static instance: TokenService;
  private redis: Redis;
  private readonly TOKEN_FAMILY_PREFIX = 'token_family:';
  private readonly CURRENT_TOKEN_PREFIX = 'current_token:';
  private readonly REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60;

  private constructor() {
    const config = getConfig();
    this.redis = new Redis(config.redisUrl, { lazyConnect: true });
  }

  public static getInstance(): TokenService {
    if (!TokenService.instance) {
      TokenService.instance = new TokenService();
    }
    return TokenService.instance;
  }

  public async connect(): Promise<void> {
    await this.redis.connect();
  }

  public async disconnect(): Promise<void> {
    await this.redis.quit();
  }

  public async storeRefreshToken(
    userId: string,
    tokenFamily: string,
    tokenId: string,
    expirationSeconds: number = this.REFRESH_TOKEN_TTL
  ): Promise<void> {
    const familyKey = `${this.TOKEN_FAMILY_PREFIX}${userId}:${tokenFamily}`;
    const currentKey = `${this.CURRENT_TOKEN_PREFIX}${userId}:${tokenFamily}`;

    await this.redis.setex(currentKey, expirationSeconds, tokenId);
    await this.redis.sadd(familyKey, tokenId);
    await this.redis.expire(familyKey, expirationSeconds);
  }

  public async validateRefreshToken(
    userId: string,
    tokenFamily: string,
    tokenId: string
  ): Promise<boolean> {
    const currentKey = `${this.CURRENT_TOKEN_PREFIX}${userId}:${tokenFamily}`;
    const storedTokenId = await this.redis.get(currentKey);

    if (!storedTokenId || storedTokenId !== tokenId) {
      return false;
    }

    return true;
  }

  public async invalidateRefreshToken(
    userId: string,
    tokenFamily: string,
    tokenId: string
  ): Promise<void> {
    const currentKey = `${this.CURRENT_TOKEN_PREFIX}${userId}:${tokenFamily}`;
    const familyKey = `${this.TOKEN_FAMILY_PREFIX}${userId}:${tokenFamily}`;

    await this.redis.del(currentKey);
    await this.redis.srem(familyKey, tokenId);
  }

  public async invalidateTokenFamily(userId: string, tokenFamily: string): Promise<void> {
    const familyKey = `${this.TOKEN_FAMILY_PREFIX}${userId}:${tokenFamily}`;
    const tokenIds = await this.redis.smembers(familyKey);

    for (const tokenId of tokenIds) {
      const currentKey = `${this.CURRENT_TOKEN_PREFIX}${userId}:${tokenFamily}`;
      await this.redis.del(currentKey);
    }

    await this.redis.del(familyKey);
  }

  public async refreshTokenFamily(
    userId: string,
    oldTokenFamily: string,
    oldTokenId: string
  ): Promise<{ newTokenFamily: string; newTokenId: string } | null> {
    const isValid = await this.validateRefreshToken(userId, oldTokenFamily, oldTokenId);
    if (!isValid) {
      await this.invalidateTokenFamily(userId, oldTokenFamily);
      return null;
    }

    const newTokenFamily = oldTokenFamily;
    const newTokenId = jwtService.generateTokenId();

    await this.invalidateRefreshToken(userId, oldTokenFamily, oldTokenId);
    await this.storeRefreshToken(userId, newTokenFamily, newTokenId);

    return { newTokenFamily, newTokenId };
  }

  public async storeCsrfToken(userId: string, csrfToken: string, ttlSeconds: number): Promise<void> {
    const key = `csrf:${userId}:${csrfToken}`;
    await this.redis.setex(key, ttlSeconds, '1');
  }

  public async validateCsrfToken(userId: string, csrfToken: string): Promise<boolean> {
    const key = `csrf:${userId}:${csrfToken}`;
    const exists = await this.redis.get(key);
    return exists === '1';
  }

  public async invalidateCsrfToken(userId: string, csrfToken: string): Promise<void> {
    const key = `csrf:${userId}:${csrfToken}`;
    await this.redis.del(key);
  }
}

export const tokenService = TokenService.getInstance();
