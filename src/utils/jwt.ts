import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getConfig } from '../config';

export interface JwtPayload {
  userId: string;
  role: string;
  iat?: number;
  exp?: number;
}

export interface RefreshTokenPayload {
  userId: string;
  tokenId: string;
  tokenFamily: string;
  iat?: number;
  exp?: number;
}

export class JwtService {
  private static instance: JwtService;
  private secret: string;
  private accessExpiresIn: string;
  private refreshExpiresIn: string;

  private constructor() {
    const config = getConfig();
    this.secret = config.jwt.secret;
    this.accessExpiresIn = config.jwt.expiresIn;
    this.refreshExpiresIn = config.jwt.refreshExpiresIn;
  }

  public static getInstance(): JwtService {
    if (!JwtService.instance) {
      JwtService.instance = new JwtService();
    }
    return JwtService.instance;
  }

  public generateAccessToken(payload: Omit<JwtPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, this.secret, { expiresIn: this.accessExpiresIn });
  }

  public generateRefreshToken(payload: Omit<RefreshTokenPayload, 'iat' | 'exp'>): string {
    return jwt.sign(payload, this.secret, { expiresIn: this.refreshExpiresIn });
  }

  public verifyAccessToken(token: string): JwtPayload {
    try {
      return jwt.verify(token, this.secret) as JwtPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Access token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid access token');
      }
      throw error;
    }
  }

  public verifyRefreshToken(token: string): RefreshTokenPayload {
    try {
      return jwt.verify(token, this.secret) as RefreshTokenPayload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Refresh token has expired');
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid refresh token');
      }
      throw error;
    }
  }

  public decodeToken(token: string): JwtPayload | RefreshTokenPayload | null {
    return jwt.decode(token) as JwtPayload | RefreshTokenPayload | null;
  }

  public generateTokenFamily(): string {
    return uuidv4();
  }

  public generateTokenId(): string {
    return uuidv4();
  }
}

export const jwtService = JwtService.getInstance();
