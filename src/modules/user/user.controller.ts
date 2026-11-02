import { Request, Response } from 'express';
import { UserService } from './user.service';
import { UserQueryDto, UpdateProfileDto, UpdateSensitiveDataDto, ReEncryptDataDto } from '../../validators/user.validator';
import { logger } from '../../utils/logger';
import { AuthenticatedRequest, requireAuth, Role } from '../../middleware/auth.middleware';

export class UserController {
  constructor(private userService: UserService) {}

  async getAllUsers(req: Request, res: Response): Promise<void> {
    try {
      const query = req.query as unknown as UserQueryDto;
      const result = await this.userService.findAll(query);

      res.status(200).json({
        status: 'success',
        data: result.users,
        pagination: {
          page: query.page || 1,
          limit: query.limit || 10,
          total: result.total,
        },
      });
    } catch (error) {
      logger.error('Get all users error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: (req as any).requestId,
      });
    }
  }

  async getUserById(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const user = await this.userService.findById(id);

      if (!user) {
        res.status(404).json({
          status: 'error',
          message: 'User not found',
          requestId: (req as any).requestId,
        });
        return;
      }

      res.status(200).json({
        status: 'success',
        data: user,
      });
    } catch (error) {
      logger.error('Get user by ID error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: (req as any).requestId,
      });
    }
  }

  async getUserMaskedData(req: Request, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const data = await this.userService.getMaskedUserData(id);

      res.status(200).json({
        status: 'success',
        data,
      });
    } catch (error) {
      logger.error('Get user masked data error', { error: (error as Error).message });
      res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        requestId: (req as any).requestId,
      });
    }
  }

  async updateProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
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

      const dto = req.body as UpdateProfileDto;
      const ip = req.ip || 'unknown';

      const user = await this.userService.updateProfile(userId, dto, ip);

      res.status(200).json({
        status: 'success',
        data: user,
      });
    } catch (error) {
      logger.error('Update profile error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: req.requestId,
      });
    }
  }

  async updateSensitiveData(req: AuthenticatedRequest, res: Response): Promise<void> {
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

      const dto = req.body as UpdateSensitiveDataDto;
      const ip = req.ip || 'unknown';

      await this.userService.updateSensitiveData(userId, dto, ip);

      res.status(200).json({
        status: 'success',
        message: 'Sensitive data updated successfully',
      });
    } catch (error) {
      logger.error('Update sensitive data error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: req.requestId,
      });
    }
  }

  async reEncryptUserData(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const dto = req.body as ReEncryptDataDto;
      const ip = req.ip || 'unknown';

      await this.userService.reEncryptData(dto.userId, dto.field!, ip);

      res.status(200).json({
        status: 'success',
        message: 'Data re-encrypted successfully',
      });
    } catch (error) {
      logger.error('Re-encrypt data error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: req.requestId,
      });
    }
  }

  async deleteUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const ip = req.ip || 'unknown';

      await this.userService.deleteUser(id, ip);

      res.status(200).json({
        status: 'success',
        message: 'User deleted successfully',
      });
    } catch (error) {
      logger.error('Delete user error', { error: (error as Error).message });
      res.status(400).json({
        status: 'error',
        message: (error as Error).message,
        requestId: req.requestId,
      });
    }
  }
}
