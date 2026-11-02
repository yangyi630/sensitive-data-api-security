import { Request, Response, NextFunction, ValidationChain } from 'express';
import { body, query, param, validationResult } from 'express-validator';

export function validate(validations: ValidationChain[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    await Promise.all(validations.map((validation) => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      next();
      return;
    }

    const extractedErrors = errors.array().map((err) => ({
      field: 'path' in err ? err.path : 'unknown',
      message: err.msg,
    }));

    res.status(400).json({
      status: 'error',
      message: 'Validation failed',
      errors: extractedErrors,
      requestId: (req as any).requestId,
    });
  };
}

export const commonValidations = {
  email: body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),

  password: body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),

  phone: body('phone')
    .optional()
    .matches(/^1[3-9]\d{9}$/)
    .withMessage('Valid Chinese phone number is required'),

  idCard: body('idCard')
    .optional()
    .matches(/^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$/)
    .withMessage('Valid ID card number is required'),

  bankCard: body('bankCard')
    .optional()
    .matches(/^\d{16,19}$/)
    .withMessage('Valid bank card number is required'),

  username: body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be 3-50 alphanumeric characters'),

  page: query('page')
    .optional()
    .isInt({ min: 1 })
    .toInt()
    .withMessage('Page must be a positive integer'),

  limit: query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .toInt()
    .withMessage('Limit must be between 1 and 100'),

  idParam: param('id')
    .isUUID()
    .withMessage('Invalid ID format'),
};

export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function sanitizeOutput(data: unknown): unknown {
  if (typeof data === 'string') {
    return escapeHtml(data);
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeOutput(item));
  }

  if (data && typeof data === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      sanitized[key] = sanitizeOutput(value);
    }
    return sanitized;
  }

  return data;
}
