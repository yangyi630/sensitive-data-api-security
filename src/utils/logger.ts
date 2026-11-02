import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { getConfig } from '../config';

const config = getConfig();

const { combine, timestamp, json, printf, colorize } = winston.format;

const maskPatterns: { pattern: RegExp; replacement: string }[] = [
  { pattern: /("password"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("pwd"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("secret"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("token"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("refreshToken"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("accessToken"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("phone"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("idCard"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("bankCard"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("email"\s*:\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /(password=)[^&\s]*/gi, replacement: '$1[REDACTED]' },
  { pattern: /(pwd=)[^&\s]*/gi, replacement: '$1[REDACTED]' },
  { pattern: /(token=)[^&\s]*/gi, replacement: '$1[REDACTED]' },
];

export function maskSensitiveData(data: unknown): unknown {
  if (typeof data === 'string') {
    let masked = data;
    for (const { pattern, replacement } of maskPatterns) {
      masked = masked.replace(pattern, replacement);
    }
    return masked;
  }

  if (Array.isArray(data)) {
    return data.map((item) => maskSensitiveData(item));
  }

  if (data && typeof data === 'object') {
    const masked: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      masked[key] = maskSensitiveData(value);
    }
    return masked;
  }

  return data;
}

const logFormat = printf(({ level, message, timestamp, ...metadata }) => {
  const maskedMetadata = maskSensitiveData(metadata);
  return JSON.stringify({
    timestamp,
    level,
    message,
    ...(typeof maskedMetadata === 'object' && maskedMetadata !== null ? maskedMetadata : { metadata: maskedMetadata }),
  });
});

const transports: winston.transport[] = [
  new winston.transports.Console({
    format: combine(
      colorize({ all: true }),
      timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      winston.format.simple()
    ),
  }),
];

if (config.nodeEnv !== 'test') {
  transports.push(
    new DailyRotateFile({
      filename: `${config.log.dir}/application-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      level: config.log.level,
      maxFiles: '30d',
      maxSize: '20m',
    })
  );

  transports.push(
    new DailyRotateFile({
      filename: `${config.log.dir}/error-%DATE%.log`,
      datePattern: 'YYYY-MM-DD',
      level: 'error',
      maxFiles: '30d',
      maxSize: '20m',
    })
  );
}

export const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : config.log.level,
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    logFormat
  ),
  defaultMeta: { service: 'secure-api' },
  transports,
});

export interface AuditLogParams {
  userId?: string;
  ip: string;
  action: string;
  resource: string;
  result: 'success' | 'failure';
  metadata?: Record<string, unknown>;
}

export function logAudit(params: AuditLogParams): void {
  logger.info('AUDIT', {
    type: 'audit',
    userId: params.userId,
    ip: params.ip,
    action: params.action,
    resource: params.resource,
    result: params.result,
    metadata: params.metadata,
  });
}

export function logSecurity(params: AuditLogParams): void {
  logger.warn('SECURITY', {
    type: 'security',
    userId: params.userId,
    ip: params.ip,
    action: params.action,
    resource: params.resource,
    result: params.result,
    metadata: params.metadata,
  });
}
