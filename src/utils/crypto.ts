import crypto from 'crypto';
import { getConfig } from '../config';

export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EncryptionError';
  }
}

export class EncryptionService {
  private static instance: EncryptionService;
  private currentKey: Buffer;
  private oldKeys: Buffer[];

  private constructor() {
    const config = getConfig();
    this.currentKey = Buffer.from(config.encryption.currentKey, 'base64');
    this.oldKeys = config.encryption.oldKeys.map((k) => Buffer.from(k, 'base64'));

    if (this.currentKey.length !== 32) {
      throw new Error('CURRENT_KEY must be 32 bytes (256 bits) when decoded');
    }
  }

  public static getInstance(): EncryptionService {
    if (!EncryptionService.instance) {
      EncryptionService.instance = new EncryptionService();
    }
    return EncryptionService.instance;
  }

  private getKeyByVersion(version: number): Buffer | null {
    if (version === 0) {
      return this.currentKey;
    }
    const oldKeyIndex = version - 1;
    if (oldKeyIndex >= 0 && oldKeyIndex < this.oldKeys.length) {
      return this.oldKeys[oldKeyIndex];
    }
    return null;
  }

  public encrypt(plaintext: string, version: number = 0): string {
    const key = this.getKeyByVersion(version);
    if (!key) {
      throw new EncryptionError(`Unknown key version: ${version}`);
    }

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');

    const authTag = cipher.getAuthTag();

    return `v${version}:${iv.toString('base64')}:${authTag.toString('base64')}:${ciphertext}`;
  }

  public decrypt(encryptedData: string): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 4) {
      throw new EncryptionError('Invalid encrypted data format');
    }

    const versionMatch = parts[0].match(/^v(\d+)$/);
    if (!versionMatch) {
      throw new EncryptionError('Invalid version format');
    }

    const version = parseInt(versionMatch[1], 10);
    const iv = Buffer.from(parts[1], 'base64');
    const authTag = Buffer.from(parts[2], 'base64');
    const ciphertext = parts[3];

    const key = this.getKeyByVersion(version);
    if (!key) {
      throw new EncryptionError(`Unknown key version: ${version}`);
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let plaintext: string;
    try {
      plaintext = decipher.update(ciphertext, 'base64', 'utf8');
      plaintext += decipher.final('utf8');
    } catch (error) {
      throw new EncryptionError('Decryption failed: authentication tag verification failed');
    }

    return plaintext;
  }

  public isVersionCurrentKey(version: number): boolean {
    return version === 0;
  }

  public getCurrentVersion(): number {
    return 0;
  }

  public rotateKey(newKey: string): void {
    const config = getConfig();
    if (config.encryption.oldKeys.length > 0) {
      const lastOldKey = config.encryption.oldKeys[config.encryption.oldKeys.length - 1];
      this.oldKeys.push(Buffer.from(lastOldKey, 'base64'));
      this.oldKeys.shift();
    }
    this.currentKey = Buffer.from(newKey, 'base64');
  }
}

export const encryptionService = EncryptionService.getInstance();
