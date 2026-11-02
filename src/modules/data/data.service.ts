import { encryptionService } from '../../services/encryption.service';
import { maskService } from '../../utils/mask';
import { logger, logAudit } from '../../utils/logger';

export interface SensitiveData {
  type: 'phone' | 'idCard' | 'bankCard';
  value: string;
}

export class DataService {
  private static instance: DataService;

  private constructor() {}

  public static getInstance(): DataService {
    if (!DataService.instance) {
      DataService.instance = new DataService();
    }
    return DataService.instance;
  }

  public encryptSensitiveData(data: string, type: SensitiveData['type']): string {
    try {
      const encrypted = encryptionService.encrypt(data);
      logger.info('Sensitive data encrypted', { type });
      return encrypted;
    } catch (error) {
      logger.error('Encryption failed', { type, error });
      throw error;
    }
  }

  public decryptSensitiveData(encryptedData: string, type: SensitiveData['type']): string {
    try {
      const decrypted = encryptionService.decrypt(encryptedData);
      logAudit({
        action: 'SENSITIVE_DATA_DECRYPTED',
        resource: 'data',
        result: 'success',
        metadata: { type },
      });
      return decrypted;
    } catch (error) {
      logAudit({
        action: 'SENSITIVE_DATA_DECRYPT_FAILED',
        resource: 'data',
        result: 'failure',
        metadata: { type, reason: (error as Error).message },
      });
      throw error;
    }
  }

  public maskSensitiveData(data: string, type: SensitiveData['type']): string {
    return maskService.maskSensitiveField(data, type);
  }

  public validateAndEncrypt(data: string, type: SensitiveData['type']): string {
    const validationRegex = this.getValidationRegex(type);

    if (!validationRegex.test(data)) {
      throw new Error(`Invalid ${type} format`);
    }

    return this.encryptSensitiveData(data, type);
  }

  private getValidationRegex(type: SensitiveData['type']): RegExp {
    switch (type) {
      case 'phone':
        return /^1[3-9]\d{9}$/;
      case 'idCard':
        return /^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/;
      case 'bankCard':
        return /^\d{16,19}$/;
      default:
        throw new Error(`Unknown type: ${type}`);
    }
  }

  public processAndStore(data: string, type: SensitiveData['type']): { encrypted: string; masked: string } {
    const encrypted = this.validateAndEncrypt(data, type);
    const masked = this.maskSensitiveData(data, type);

    return { encrypted, masked };
  }
}

export const dataService = DataService.getInstance();
