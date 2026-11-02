import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { EncryptionService } from '../src/utils/crypto';
import { MaskService } from '../src/utils/mask';
import { JwtService } from '../src/utils/jwt';
import { PasswordService } from '../src/services/password.service';

jest.mock('../src/config', () => ({
  getConfig: () => ({
    encryption: {
      currentKey: Buffer.from('a'.repeat(32), 'base64').toString('base64'),
      oldKeys: [],
    },
    jwt: {
      secret: 'test-jwt-secret-key-minimum-32-characters',
      expiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    security: {
      bcryptRounds: 10,
    },
  }),
}));

describe('EncryptionService', () => {
  let encryptionService: EncryptionService;

  beforeEach(() => {
    encryptionService = new EncryptionService();
  });

  describe('encrypt', () => {
    it('should encrypt plaintext and return formatted string', () => {
      const plaintext = '13800138000';
      const encrypted = encryptionService.encrypt(plaintext);

      expect(encrypted).toMatch(/^v0:[^:]+:[^:]+:.+$/);
    });

    it('should produce different ciphertexts for same plaintext (due to random IV)', () => {
      const plaintext = '13800138000';
      const encrypted1 = encryptionService.encrypt(plaintext);
      const encrypted2 = encryptionService.encrypt(plaintext);

      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe('decrypt', () => {
    it('should decrypt encrypted data correctly', () => {
      const plaintext = '13800138000';
      const encrypted = encryptionService.encrypt(plaintext);
      const decrypted = encryptionService.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should throw error for invalid format', () => {
      expect(() => encryptionService.decrypt('invalid-data')).toThrow();
    });

    it('should throw error for tampered auth tag', () => {
      const encrypted = encryptionService.encrypt('test');
      const parts = encrypted.split(':');
      parts[2] = Buffer.from('tampered').toString('base64');
      const tampered = parts.join(':');

      expect(() => encryptionService.decrypt(tampered)).toThrow();
    });
  });
});

describe('MaskService', () => {
  let maskService: MaskService;

  beforeEach(() => {
    maskService = new MaskService();
  });

  describe('maskPhone', () => {
    it('should mask phone number correctly', () => {
      const phone = '13800138000';
      const masked = maskService.maskPhone(phone);

      expect(masked).toBe('138****8000');
    });

    it('should handle short phone numbers', () => {
      const phone = '123';
      const masked = maskService.maskPhone(phone);

      expect(masked).toBe('******');
    });
  });

  describe('maskIdCard', () => {
    it('should mask ID card correctly', () => {
      const idCard = '110101199001011234';
      const masked = maskService.maskIdCard(idCard);

      expect(masked).toBe('110***********1234');
    });
  });

  describe('maskBankCard', () => {
    it('should mask bank card correctly', () => {
      const bankCard = '6222021234567890123';
      const masked = maskService.maskBankCard(bankCard);

      expect(masked).toBe('6222**********0123');
    });
  });

  describe('maskEmail', () => {
    it('should mask email correctly', () => {
      const email = 'test@example.com';
      const masked = maskService.maskEmail(email);

      expect(masked).toBe('t***@example.com');
    });
  });
});

describe('JwtService', () => {
  let jwtService: JwtService;

  beforeEach(() => {
    jwtService = new JwtService();
  });

  describe('generateAccessToken', () => {
    it('should generate valid access token', () => {
      const payload = { userId: 'user-123', role: 'user' };
      const token = jwtService.generateAccessToken(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
    });

    it('should include correct payload after verification', () => {
      const payload = { userId: 'user-123', role: 'admin' };
      const token = jwtService.generateAccessToken(payload);
      const decoded = jwtService.verifyAccessToken(token);

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.role).toBe(payload.role);
    });
  });

  describe('generateRefreshToken', () => {
    it('should generate refresh token with tokenId and tokenFamily', () => {
      const payload = { userId: 'user-123', tokenFamily: 'family-1', tokenId: 'token-1' };
      const token = jwtService.generateRefreshToken(payload);
      const decoded = jwtService.verifyRefreshToken(token);

      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.tokenFamily).toBe(payload.tokenFamily);
      expect(decoded.tokenId).toBe(payload.tokenId);
    });
  });

  describe('verifyAccessToken', () => {
    it('should throw error for invalid token', () => {
      expect(() => jwtService.verifyAccessToken('invalid-token')).toThrow();
    });

    it('should throw error for tampered token', () => {
      const token = jwtService.generateAccessToken({ userId: 'user-123', role: 'user' });
      const tampered = token.slice(0, -5) + 'xxxxx';

      expect(() => jwtService.verifyAccessToken(tampered)).toThrow();
    });
  });
});

describe('PasswordService', () => {
  let passwordService: PasswordService;

  beforeEach(() => {
    passwordService = new PasswordService();
  });

  describe('hashPassword', () => {
    it('should hash password', async () => {
      const password = 'TestPassword123';
      const hash = await passwordService.hashPassword(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50);
    });

    it('should produce different hashes for same password', async () => {
      const password = 'TestPassword123';
      const hash1 = await passwordService.hashPassword(password);
      const hash2 = await passwordService.hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verifyPassword', () => {
    it('should verify correct password', async () => {
      const password = 'TestPassword123';
      const hash = await passwordService.hashPassword(password);
      const isValid = await passwordService.verifyPassword(password, hash);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'TestPassword123';
      const hash = await passwordService.hashPassword(password);
      const isValid = await passwordService.verifyPassword('WrongPassword', hash);

      expect(isValid).toBe(false);
    });
  });
});

describe('ReplayProtection', () => {
  it('should validate timestamp format', () => {
    const now = Date.now();
    const validTimestamp = now.toString();
    const invalidTimestamp = 'not-a-number';

    expect(isNaN(parseInt(validTimestamp, 10))).toBe(false);
    expect(isNaN(parseInt(invalidTimestamp, 10))).toBe(true);
  });
});

describe('Input Validation', () => {
  const phoneRegex = /^1[3-9]\d{9}$/;
  const idCardRegex = /^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/;
  const bankCardRegex = /^\d{16,19}$/;
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/;

  describe('Phone validation', () => {
    it('should accept valid phone numbers', () => {
      expect(phoneRegex.test('13800138000')).toBe(true);
      expect(phoneRegex.test('15912345678')).toBe(true);
    });

    it('should reject invalid phone numbers', () => {
      expect(phoneRegex.test('12345678901')).toBe(false);
      expect(phoneRegex.test('1380013800')).toBe(false);
      expect(phoneRegex.test('abc')).toBe(false);
    });
  });

  describe('ID Card validation', () => {
    it('should accept valid ID cards', () => {
      expect(idCardRegex.test('110101199001011234')).toBe(true);
    });

    it('should reject invalid ID cards', () => {
      expect(idCardRegex.test('123456789012345678')).toBe(false);
    });
  });

  describe('Bank Card validation', () => {
    it('should accept valid bank cards', () => {
      expect(bankCardRegex.test('6222021234567890123')).toBe(true);
      expect(bankCardRegex.test('1234567890123456')).toBe(true);
    });

    it('should reject invalid bank cards', () => {
      expect(bankCardRegex.test('123')).toBe(false);
    });
  });

  describe('Password validation', () => {
    it('should accept strong passwords', () => {
      expect(passwordRegex.test('Password123')).toBe(true);
      expect(passwordRegex.test('Admin1234')).toBe(true);
    });

    it('should reject weak passwords', () => {
      expect(passwordRegex.test('password')).toBe(false);
      expect(passwordRegex.test('PASSWORD123')).toBe(false);
      expect(passwordRegex.test('12345678')).toBe(false);
    });
  });
});
