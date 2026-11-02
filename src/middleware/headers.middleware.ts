import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import { getConfig } from '../../config';

export function getSecurityHeadersMiddleware() {
  const config = getConfig();

  return [
    helmet(),
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'cdn.example.com'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
      reportOnly: config.nodeEnv === 'development',
    }),
    helmet.hsts({
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    }),
    helmet.frameguard({
      action: 'deny',
    }),
    helmet.noSniff(),
    helmet.permittedCrossDomainPolicies({
      permittedPolicies: 'none',
    }),
    helmet.referrerPolicy({
      policy: 'strict-origin-when-cross-origin',
    }),
  ];
}

export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
}
