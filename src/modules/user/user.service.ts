import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../../entity/user.entity';
import { UpdateProfileDto, UserQueryDto, UpdateSensitiveDataDto } from '../../validators/user.validator';
import { passwordService } from '../../services/password.service';
import { encryptionService } from '../../services/encryption.service';
import { maskService } from '../../utils/mask';
import { logger, logAudit } from '../../utils/logger';

export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>
  ) {}

  async findAll(query: UserQueryDto): Promise<{ users: Partial<User>[]; total: number }> {
    const { page = 1, limit = 10, role, search } = query;
    const skip = (page - 1) * limit;

    const queryBuilder = this.userRepository.createQueryBuilder('user');

    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    if (search) {
      queryBuilder.andWhere(
        '(user.username ILIKE :search OR user.email ILIKE :search OR user.fullName ILIKE :search)',
        { search: `%${search}%` }
      );
    }

    const [users, total] = await queryBuilder
      .skip(skip)
      .take(limit)
      .orderBy('user.createdAt', 'DESC')
      .getManyAndCount();

    return {
      users: users.map((user) => this.sanitizeUser(user)),
      total,
    };
  }

  async findById(id: string): Promise<Partial<User> | null> {
    const user = await this.userRepository.findOne({ where: { id } });
    return user ? this.sanitizeUser(user) : null;
  }

  async updateProfile(userId: string, dto: UpdateProfileDto, ip: string): Promise<Partial<User>> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    if (dto.fullName !== undefined) {
      user.fullName = dto.fullName;
    }

    await this.userRepository.save(user);

    logAudit({
      userId,
      ip,
      action: 'PROFILE_UPDATED',
      resource: 'user',
      result: 'success',
      metadata: { updatedFields: Object.keys(dto) },
    });

    return this.sanitizeUser(user);
  }

  async updateSensitiveData(userId: string, dto: UpdateSensitiveDataDto, ip: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    if (dto.phone !== undefined) {
      user.phoneEncrypted = encryptionService.encrypt(dto.phone);
    }
    if (dto.idCard !== undefined) {
      user.idCardEncrypted = encryptionService.encrypt(dto.idCard);
    }
    if (dto.bankCard !== undefined) {
      user.bankCardEncrypted = encryptionService.encrypt(dto.bankCard);
    }

    await this.userRepository.save(user);

    logAudit({
      userId,
      ip,
      action: 'SENSITIVE_DATA_UPDATED',
      resource: 'user',
      result: 'success',
      metadata: { updatedFields: Object.keys(dto) },
    });
  }

  async deleteUser(userId: string, ip: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    await this.userRepository.remove(user);

    logAudit({
      userId,
      ip,
      action: 'USER_DELETED',
      resource: 'user',
      result: 'success',
      metadata: { deletedUserId: userId },
    });
  }

  async reEncryptData(userId: string, field: 'phone' | 'idCard' | 'bankCard', ip: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    let encryptedField: string | undefined;

    switch (field) {
      case 'phone':
        encryptedField = user.phoneEncrypted;
        break;
      case 'idCard':
        encryptedField = user.idCardEncrypted;
        break;
      case 'bankCard':
        encryptedField = user.bankCardEncrypted;
        break;
    }

    if (!encryptedField) {
      throw new Error(`No ${field} data to re-encrypt`);
    }

    const decrypted = encryptionService.decrypt(encryptedField);
    const reEncrypted = encryptionService.encrypt(decrypted);

    switch (field) {
      case 'phone':
        user.phoneEncrypted = reEncrypted;
        break;
      case 'idCard':
        user.idCardEncrypted = reEncrypted;
        break;
      case 'bankCard':
        user.bankCardEncrypted = reEncrypted;
        break;
    }

    await this.userRepository.save(user);

    logAudit({
      userId,
      ip,
      action: 'DATA_REENCRYPTED',
      resource: 'user',
      result: 'success',
      metadata: { field },
    });
  }

  async getMaskedUserData(userId: string): Promise<Record<string, unknown>> {
    const user = await this.userRepository.findOne({ where: { id: userId } });

    if (!user) {
      throw new Error('User not found');
    }

    let phone: string | undefined;
    let idCard: string | undefined;
    let bankCard: string | undefined;

    try {
      if (user.phoneEncrypted) {
        const decrypted = encryptionService.decrypt(user.phoneEncrypted);
        phone = maskService.maskPhone(decrypted);
      }
    } catch {
      phone = '[ERROR]';
    }

    try {
      if (user.idCardEncrypted) {
        const decrypted = encryptionService.decrypt(user.idCardEncrypted);
        idCard = maskService.maskIdCard(decrypted);
      }
    } catch {
      idCard = '[ERROR]';
    }

    try {
      if (user.bankCardEncrypted) {
        const decrypted = encryptionService.decrypt(user.bankCardEncrypted);
        bankCard = maskService.maskBankCard(decrypted);
      }
    } catch {
      bankCard = '[ERROR]';
    }

    logAudit({
      userId,
      action: 'USER_DATA_ACCESSED',
      resource: 'user',
      result: 'success',
      metadata: { action: 'masked' },
    });

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      fullName: maskService.maskName(user.fullName),
      phone,
      idCard,
      bankCard,
    };
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
}
