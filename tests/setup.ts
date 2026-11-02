import dotenv from 'dotenv';
dotenv.config();

jest.mock('../src/config', () => ({
  getConfig: () => ({
    encryption: {
      currentKey: Buffer.from('test-current-key-32-bytes!!').toString('base64'),
      oldKeys: [],
    },
    jwt: {
      secret: 'test-jwt-secret-key-minimum-32-characters-long',
      expiresIn: '15m',
      refreshExpiresIn: '7d',
    },
    security: {
      bcryptRounds: 10,
    },
    redisUrl: 'redis://localhost:6379',
    rateLimit: {
      windowMs: 60000,
      maxRequests: 100,
      sensitiveMax: 5,
    },
    nonceExpiresSeconds: 300,
    timestampToleranceMs: 180000,
    log: {
      level: 'error',
      dir: './logs',
    },
    nodeEnv: 'test',
  }),
}));

beforeAll(() => {
  process.env.NODE_ENV = 'test';
});
