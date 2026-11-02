import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto, LoginDto, RefreshTokenDto, ChangePasswordDto } from '../../validators/user.validator';
import { tokenService } from '../../services/token.service';
import { logger } from '../../utils/logger';
import { AuthenticatedRequest } from '../../middleware/auth.middleware';

export class AuthController {
  constructor(private authService: AuthService) {}

  async register(req: Request, res: Response): Promise<void> {
    try {
      const dto = req.body as RegisterDto;
      const ip = req.ip || 'unknown';

      const result = await this.authService.register(dto, ip);

      res.cookie('csrf-token', result.csrfToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(201).json({
        status: 'success',
        data: {
          user: result.user,
          accessToken: result.accessToken,
          csrfToken: result.csrfToken,
        },
      });
    } catch (error) {
      logger.error('Registration error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: (req as any).requestId,
      });
    }
  }

  async login(req: Request, res: Response): Promise<void> {
    try {
      const dto = req.body as LoginDto;
      const ip = req.ip || 'unknown';

      const result = await this.authService.login(dto, ip);

      res.cookie('csrf-token', result.csrfToken, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });

      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        status: 'success',
        data: {
          user: result.user,
          accessToken: result.accessToken,
          csrfToken: result.csrfToken,
        },
      });
    } catch (error) {
      logger.error('Login error', { error: (error as Error).message });
      res.status(401).json({
        status: 'error',
        message: 'Invalid credentials',
        requestId: (req as any).requestId,
      });
    }
  }

  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const refreshToken = req.cookies?.refreshToken || (req.body as RefreshTokenDto)?.refreshToken;

      if (!refreshToken) {
        res.status(400).json({
          status: 'error',
          message: 'Refresh token required',
          requestId: (req as any).requestId,
        });
        return;
      }

      const ip = req.ip || 'unknown';
      const result = await this.authService.refreshToken(refreshToken, ip);

      res.cookie('refreshToken', result.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh',
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        status: 'success',
        data: {
          accessToken: result.accessToken,
        },
      });
    } catch (error) {
      logger.error('Token refresh error', { error: (error as Error).message });
      res.status(401).json({
        status: 'error',
        message: (error as Error).message,
        requestId: (req as any).requestId,
      });
    }
  }

  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.userId;
      const ip = req.ip || 'unknown';

      if (userId) {
        await this.authService.logout(userId, ip);
      }

      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh',
      });

      res.clearCookie('csrf-token', {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
      });

      res.status(200).json({
        status: 'success',
        message: 'Logged out successfully',
      });
    } catch (error) {
      logger.error('Logout error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: req.requestId,
      });
    }
  }

  async changePassword(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({
          status: 'error',
          message: 'Authentication required',
          requestId: req.requestId,
        });
        return;
      }

      const { currentPassword, newPassword } = req.body as ChangePasswordDto;
      const ip = req.ip || 'unknown';

      await this.authService.changePassword(userId, currentPassword, newPassword, ip);

      res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/api/auth/refresh',
      });

      res.status(200).json({
        status: 'success',
        message: 'Password changed successfully. Please login again.',
      });
    } catch (error) {
      logger.error('Change password error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: req.requestId,
      });
    }
  }

  async getProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({
          status: 'error',
          message: 'Authentication required',
          requestId: req.requestId,
        });
        return;
      }

      const maskedProfile = await this.authService.getMaskedProfile(userId);

      res.status(200).json({
        status: 'success',
        data: maskedProfile,
      });
    } catch (error) {
      logger.error('Get profile error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: req.requestId,
      });
    }
  }

  async getDecryptedProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        res.status(401).json({
          status: 'error',
          message: 'Authentication required',
          requestId: req.requestId,
        });
        return;
      }

      const profile = await this.authService.getDecryptedProfile(userId);

      res.status(200).json({
        status: 'success',
        data: profile,
      });
    } catch (error) {
      logger.error('Get decrypted profile error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: req.requestId,
      });
    }
  }
}
