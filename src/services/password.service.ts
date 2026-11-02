import bcrypt from 'bcrypt';
import { getConfig } from '../config';

export class PasswordService {
  private static instance: PasswordService;
  private bcryptRounds: number;

  private constructor() {
    const config = getConfig();
    this.bcryptRounds = config.security.bcryptRounds;
  }

  public static getInstance(): PasswordService {
    if (!PasswordService.instance) {
      PasswordService.instance = new PasswordService();
    }
    return PasswordService.instance;
  }

  public async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.bcryptRounds);
  }

  public async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }
}

export const passwordService = PasswordService.getInstance();
