import {
  IsString,
  IsEmail,
  IsOptional,
  IsEnum,
  IsPhoneNumber,
  IsDateString,
  MinLength,
  MaxLength,
  Matches,
  IsUUID,
  IsInt,
  Min,
  Max,
} from 'class-validator';
import { Type } from 'class-transformer';
import { Role } from '../middleware/auth.middleware';

export class RegisterDto {
  @IsString()
  @MinLength(3)
  @MaxLength(50)
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message: 'Username can only contain alphanumeric characters and underscores',
  })
  username!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  password!: string;

  @IsString()
  @MaxLength(100)
  fullName!: string;

  @IsOptional()
  @IsPhoneNumber('CN')
  phone?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/, {
    message: 'Invalid ID card format',
  })
  idCard?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{16,19}$/, {
    message: 'Invalid bank card format',
  })
  bankCard?: string;
}

export class LoginDto {
  @IsString()
  username!: string;

  @IsString()
  password!: string;
}

export class RefreshTokenDto {
  @IsOptional()
  @IsString()
  refreshToken?: string;
}

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(100)
  fullName?: string;

  @IsOptional()
  @IsPhoneNumber('CN')
  phone?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/, {
    message: 'Invalid ID card format',
  })
  idCard?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{16,19}$/, {
    message: 'Invalid bank card format',
  })
  bankCard?: string;
}

export class UpdateSensitiveDataDto {
  @IsOptional()
  @IsPhoneNumber('CN')
  phone?: string;

  @IsOptional()
  @IsString()
  @Matches(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/, {
    message: 'Invalid ID card format',
  })
  idCard?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{16,19}$/, {
    message: 'Invalid bank card format',
  })
  bankCard?: string;
}

export class ChangePasswordDto {
  @IsString()
  currentPassword!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
    message: 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
  })
  newPassword!: string;
}

export class UserQueryDto {
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 10;

  @IsOptional()
  @IsString()
  role?: string;

  @IsOptional()
  @IsString()
  search?: string;
}

export class ReEncryptDataDto {
  @IsUUID()
  userId!: string;

  @IsOptional()
  @IsString()
  field?: 'phone' | 'idCard' | 'bankCard';
}
