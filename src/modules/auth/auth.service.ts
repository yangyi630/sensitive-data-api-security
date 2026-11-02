import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../../entity/user.entity';
import { RegisterDto, LoginDto, UpdateProfileDto } from '../../validators/user.validator';
import { passwordService } from '../password.service';
import { encryptionService } from '../encryption.service';
import { jwtService } from '../../utils/jwt';
import { tokenService } from '../token.service';
import { maskService } from '../../utils/mask';
import { logger, logAudit } from '../../utils/logger';

export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {}

  async register(dto: RegisterDto, ip: string): Promise<{
    user: Partial<User>;
    accessToken: string;
    refreshToken: string;
    csrfToken: string;
  }> {
    const existingUser = await this.userRepository.findOne({
      where: [{ username: dto.username }, { email: dto.email }],
    });

    if (existingUser) {
      throw new Error('Username or email already exists');
    }

    const passwordHash = await passwordService.hashPassword(dto.password);

    const user = this.userRepository.create({
      username: dto.username,
      email: dto.email,
      passwordHash,
      fullName: dto.fullName,
      role: 'user',
    });

    if (dto.phone) {
      user.phoneEncrypted = encryptionService.encrypt(dto.phone);
    }
    if (dto.idCard) {
      user.idCardEncrypted = encryptionService.encrypt(dto.idCard);
    }
    if (dto.bankCard) {
      user.bankCardEncrypted = encryptionService.encrypt(dto.bankCard);
    }

    await this.userRepository.save(user);

    const tokenFamily = jwtService.generateTokenFamily();
    const tokenId = jwtService.generateTokenId();
    const accessToken = jwtService.generateAccessToken({ userId: user.id, role: user.role });
    const refreshToken = jwtService.generateRefreshToken({
      userId: user.id,
      tokenFamily,
      tokenId,
    });

    await tokenService.storeRefreshToken(user.id, tokenFamily, tokenId, 7 * 24 * 60 * 60);

    const csrfToken = jwtService.generateTokenId();
    await tokenService.storeCsrfToken(user.id, csrfToken, 24 * 60 * 60);

    logAudit({
      userId: user.id,
      ip,
      action: 'USER_REGISTERED',
      resource: 'auth',
      result: 'success',
      metadata: { username: user.username },
    });

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      csrfToken,
    };
  }

  async login(dto: LoginDto, ip: string): Promise<{
    user: Partial<User>;
    accessToken: string;
    refreshToken: string;
    csrfToken: string;
  }> {
    const user = await this.userRepository.findOne({
      where: { username: dto.username },
    });

    if (!user) {
      logAudit({
        ip,
        action: 'LOGIN_FAILED',
        resource: 'auth',
        result: 'failure',
        metadata: { username: dto.username, reason: 'User not found' },
      });
      throw new Error('Invalid credentials');
    }

    const isPasswordValid = await passwordService.verifyPassword(dto.password, user.passwordHash);

    if (!isPasswordValid) {
      logAudit({
        userId: user.id,
        ip,
        action: 'LOGIN_FAILED',
        resource: 'auth',
        result: 'failure',
        metadata: { reason: 'Invalid password' },
      });
      throw new Error('Invalid credentials');
    }

    user.lastLoginAt = new Date();
    user.lastLoginIp = ip;
    user.isActive = true;
    await this.userRepository.save(user);

    const tokenFamily = jwtService.generateTokenFamily();
    const tokenId = jwtService.generateTokenId();
    const accessToken = jwtService.generateAccessToken({ userId: user.id, role: user.role });
    const refreshToken = jwtService.generateRefreshToken({
      userId: user.id,
      tokenFamily,
      tokenId,
    });

    await tokenService.storeRefreshToken(user.id, tokenFamily, tokenId, 7 * 24 * 60 * 60);

    const csrfToken = jwtService.generateTokenId();
    await tokenService.storeCsrfToken(user.id, csrfToken, 24 * 60 * 60);

    logAudit({
      userId: user.id,
      ip,
      action: 'LOGIN_SUCCESS',
      resource: 'auth',
      result: 'success',
    });

    return {
      user: this.sanitizeUser(user),
      accessToken,
      refreshToken,
      csrfToken,
    };
  }

  async refreshToken(refreshToken: string, ip: string): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    try {
      const payload = jwtService.verifyRefreshToken(refreshToken);
      const { userId, tokenFamily, tokenId } = payload;

      const isValid = await tokenService.validateRefreshToken(userId, tokenFamily, tokenId);

      if (!isValid) {
        await tokenService.invalidateTokenFamily(userId, tokenFamily);
        logAudit({
          userId,
          ip,
          action: 'REFRESH_TOKEN_REUSED',
          resource: 'auth',
          result: 'failure',
          metadata: { reason: 'Token reuse detected' },
        });
        throw new Error('Invalid refresh token');
      }

      const result = await tokenService.refreshTokenFamily(userId, tokenFamily, tokenId);

      if (!result) {
        logAudit({
          userId,
          ip,
          action: 'REFRESH_TOKEN_INVALIDATED',
          resource: 'auth',
          result: 'failure',
          metadata: { reason: 'Token family invalidated' },
        });
        throw new Error('Session invalidated');
      }

      const user = await this.userRepository.findOne({ where: { id: userId } });
      if (!user) {
        throw new Error('User not found');
      }

      const newAccessToken = jwtService.generateAccessToken({ userId: user.id, role: user.role });
      const newRefreshToken = jwtService.generateRefreshToken({
        userId: user.id,
        tokenFamily: result.newTokenFamily,
        tokenId: result.newTokenId,
      });

      logAudit({
        userId: user.id,
        ip,
        action: 'TOKEN_REFRESHED',
        resource: 'auth',
        result: 'success',
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      logAudit({
        ip,
        action: 'REFRESH_TOKEN_FAILED',
        resource: 'auth',
        result: 'failure',
        metadata: { reason: (error as Error).message },
      });
      throw error;
    }
  }

  async logout(userId: string, ip: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (user) {
      logAudit({
        userId: user.id,
        ip,
        action: 'LOGOUT',
        resource: 'auth',
        result: 'success',
      });
    }
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string, ip: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    const isPasswordValid = await passwordService.verifyPassword(currentPassword, user.passwordHash);

    if (!isPasswordValid) {
      logAudit({
        userId,
        ip,
        action: 'PASSWORD_CHANGE_FAILED',
        resource: 'auth',
        result: 'failure',
        metadata: { reason: 'Invalid current password' },
      });
      throw new Error('Invalid current password');
    }

    user.passwordHash = await passwordService.hashPassword(newPassword);
    await this.userRepository.save(user);

    logAudit({
      userId,
      ip,
      action: 'PASSWORD_CHANGED',
      resource: 'auth',
      result: 'success',
    });
  }

  private sanitizeUser(user: User): Partial<User> {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async getMaskedProfile(userId: string): Promise<Record<string, unknown>> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    let phone: string | undefined;
    let idCard: string | undefined;
    let bankCard: string | undefined;

    try {
      if (user.phoneEncrypted) {
        phone = encryptionService.decrypt(user.phoneEncrypted);
        phone = maskService.maskPhone(phone);
      }
    } catch {
      phone = '[DECRYPTION_ERROR]';
    }

    try {
      if (user.idCardEncrypted) {
        idCard = encryptionService.decrypt(user.idCardEncrypted);
        idCard = maskService.maskIdCard(idCard);
      }
    } catch {
      idCard = '[DECRYPTION_ERROR]';
    }

    try {
      if (user.bankCardEncrypted) {
        bankCard = encryptionService.decrypt(user.bankCardEncrypted);
        bankCard = maskService.maskBankCard(bankCard);
      }
    } catch {
      bankCard = '[DECRYPTION_ERROR]';
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: maskService.maskName(user.fullName),
      role: user.role,
      phone,
      idCard,
      bankCard,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }

  async getDecryptedProfile(userId: string): Promise<Record<string, unknown>> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    logAudit({
      userId,
      action: 'SENSITIVE_DATA_ACCESS',
      resource: 'profile',
      result: 'success',
      metadata: { fields: ['phone', 'idCard', 'bankCard'] },
    });

    let phone: string | undefined;
    let idCard: string | undefined;
    let bankCard: string | undefined;

    try {
      if (user.phoneEncrypted) {
        phone = encryptionService.decrypt(user.phoneEncrypted);
      }
    } catch {
      phone = '[DECRYPTION_ERROR]';
    }

    try {
      if (user.idCardEncrypted) {
        idCard = encryptionService.decrypt(user.idCardEncrypted);
      }
    } catch {
      idCard = '[DECRYPTION_ERROR]';
    }

    try {
      if (user.bankCardEncrypted) {
        bankCard = encryptionService.decrypt(user.bankCardEncrypted);
      }
    } catch {
      bankCard = '[DECRYPTION_ERROR]';
    }

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: user.fullName,
      role: user.role,
      phone,
      idCard,
      bankCard,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }
}
