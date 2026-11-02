export class AppConfig {
  public nodeEnv: string;
  public port: number;
  public apiBaseUrl: string;
  public db: {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
  };
  public redisUrl: string;
  public jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
  };
  public encryption: {
    currentKey: string;
    oldKeys: string[];
  };
  public cors: {
    origins: string[];
  };
  public rateLimit: {
    windowMs: number;
    maxRequests: number;
    sensitiveMax: number;
  };
  public security: {
    bcryptRounds: number;
    csrfTokenExpiresIn: string;
    nonceExpiresSeconds: number;
    timestampToleranceMs: number;
  };
  public log: {
    level: string;
    dir: string;
  };
}

export function loadConfig(): AppConfig {
  const requiredVars = [
    'NODE_ENV',
    'PORT',
    'DB_HOST',
    'DB_PORT',
    'DB_USERNAME',
    'DB_PASSWORD',
    'DB_DATABASE',
    'REDIS_URL',
    'JWT_SECRET',
    'CURRENT_KEY',
    'CORS_ORIGINS',
  ];

  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      throw new Error(`Missing required environment variable: ${varName}`);
    }
  }

  const config: AppConfig = {
    nodeEnv: process.env.NODE_ENV || 'development',
    port: parseInt(process.env.PORT || '3000', 10),
    apiBaseUrl: process.env.API_BASE_URL || '/api',
    db: {
      host: process.env.DB_HOST!,
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USERNAME!,
      password: process.env.DB_PASSWORD!,
      database: process.env.DB_DATABASE!,
    },
    redisUrl: process.env.REDIS_URL!,
    jwt: {
      secret: process.env.JWT_SECRET!,
      expiresIn: process.env.JWT_EXPIRES_IN || '15m',
      refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    },
    encryption: {
      currentKey: process.env.CURRENT_KEY!,
      oldKeys: process.env.OLD_KEYS ? process.env.OLD_KEYS.split(',') : [],
    },
    cors: {
      origins: process.env.CORS_ORIGINS!.split(',').map((s) => s.trim()),
    },
    rateLimit: {
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
      sensitiveMax: parseInt(process.env.RATE_LIMIT_SENSITIVE_MAX || '5', 10),
    },
    security: {
      bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '10', 10),
      csrfTokenExpiresIn: process.env.CSRF_TOKEN_EXPIRES_IN || '24h',
      nonceExpiresSeconds: parseInt(process.env.NONCE_EXPIRES_SECONDS || '300', 10),
      timestampToleranceMs: parseInt(process.env.TIMESTAMP_TOLERANCE_MS || '180000', 10),
    },
    log: {
      level: process.env.LOG_LEVEL || 'info',
      dir: process.env.LOG_DIR || 'logs',
    },
  };

  return config;
}

let configInstance: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (!configInstance) {
    configInstance = loadConfig();
  }
  return configInstance;
}
