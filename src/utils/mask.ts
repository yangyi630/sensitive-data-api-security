export class MaskService {
  private static instance: MaskService;

  private constructor() {}

  public static getInstance(): MaskService {
    if (!MaskService.instance) {
      MaskService.instance = new MaskService();
    }
    return MaskService.instance;
  }

  public maskPhone(phone: string): string {
    if (!phone || phone.length < 11) {
      return this.maskDefault(phone);
    }
    const visibleStart = phone.substring(0, 3);
    const visibleEnd = phone.substring(phone.length - 4);
    return `${visibleStart}****${visibleEnd}`;
  }

  public maskIdCard(idCard: string): string {
    if (!idCard || idCard.length < 7) {
      return this.maskDefault(idCard);
    }
    const visibleStart = idCard.substring(0, 3);
    const visibleEnd = idCard.substring(idCard.length - 4);
    return `${visibleStart}**********${visibleEnd}`;
  }

  public maskBankCard(bankCard: string): string {
    if (!bankCard || bankCard.length < 8) {
      return this.maskDefault(bankCard);
    }
    const visibleStart = bankCard.substring(0, 4);
    const visibleEnd = bankCard.substring(bankCard.length - 4);
    return `${visibleStart}**********${visibleEnd}`;
  }

  public maskEmail(email: string): string {
    if (!email || !email.includes('@')) {
      return this.maskDefault(email);
    }
    const [localPart, domain] = email.split('@');
    if (!localPart || !domain) {
      return this.maskDefault(email);
    }
    const maskedLocal = localPart.length > 1
      ? `${localPart[0]}***`
      : `${localPart[0]}**`;
    return `${maskedLocal}@${domain}`;
  }

  public maskName(name: string): string {
    if (!name || name.length < 2) {
      return this.maskDefault(name);
    }
    if (name.length === 2) {
      return `${name[0]}*`;
    }
    const visibleStart = name.substring(0, 2);
    return `${visibleStart}${'*'.repeat(name.length - 2)}`;
  }

  public maskAddress(address: string, visibleChars: number = 4): string {
    if (!address || address.length <= visibleChars) {
      return this.maskDefault(address);
    }
    const visible = address.substring(0, visibleChars);
    return `${visible}${'*'.repeat(Math.min(address.length - visibleChars, 10))}`;
  }

  private maskDefault(value: string | undefined | null): string {
    if (!value) {
      return '[REDACTED]';
    }
    return '*'.repeat(Math.min(value.length, 8));
  }

  public maskSensitiveField(value: string, fieldType: 'phone' | 'idCard' | 'bankCard' | 'email' | 'name' | 'address'): string {
    switch (fieldType) {
      case 'phone':
        return this.maskPhone(value);
      case 'idCard':
        return this.maskIdCard(value);
      case 'bankCard':
        return this.maskBankCard(value);
      case 'email':
        return this.maskEmail(value);
      case 'name':
        return this.maskName(value);
      case 'address':
        return this.maskAddress(value);
      default:
        return this.maskDefault(value);
    }
  }
}

export const maskService = MaskService.getInstance();
