import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Secure API - Sensitive Data Encryption & Security Protection',
      version: '1.0.0',
      description: 'API documentation for the secure backend with sensitive data encryption and comprehensive security features',
      contact: {
        name: 'API Support',
      },
    },
    servers: [
      {
        url: '/api',
        description: 'API server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
          description: 'Enter your access token',
        },
        cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'refreshToken',
          description: 'HTTP-only cookie containing refresh token',
        },
        csrfHeader: {
          type: 'apiKey',
          in: 'header',
          name: 'X-CSRF-Token',
          description: 'CSRF token for state-changing requests',
        },
      },
      schemas: {
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            username: { type: 'string' },
            email: { type: 'string', format: 'email' },
            fullName: { type: 'string' },
            role: { type: 'string', enum: ['admin', 'user', 'auditor'] },
            isActive: { type: 'boolean' },
            lastLoginAt: { type: 'string', format: 'date-time' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
        MaskedProfile: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            username: { type: 'string' },
            email: { type: 'string', format: 'email' },
            fullName: { type: 'string', example: '张*' },
            phone: { type: 'string', example: '138****1234' },
            idCard: { type: 'string', example: '110***********1234' },
            bankCard: { type: 'string', example: '6225***********1234' },
          },
        },
        AuthResponse: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'success' },
            data: {
              type: 'object',
              properties: {
                user: { $ref: '#/components/schemas/User' },
                accessToken: { type: 'string' },
                csrfToken: { type: 'string' },
              },
            },
          },
        },
        Error: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'error' },
            message: { type: 'string' },
            requestId: { type: 'string' },
          },
        },
        ValidationError: {
          type: 'object',
          properties: {
            status: { type: 'string', example: 'error' },
            message: { type: 'string' },
            errors: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  field: { type: 'string' },
                  message: { type: 'string' },
                },
              },
            },
            requestId: { type: 'string' },
          },
        },
      },
    },
    security: [
      { bearerAuth: [] },
      { cookieAuth: [] },
    ],
    tags: [
      { name: 'Auth', description: 'Authentication endpoints' },
      { name: 'User', description: 'User management endpoints' },
      { name: 'Data', description: 'Data encryption and masking endpoints' },
    ],
    paths: {
      '/auth/register': {
        post: {
          tags: ['Auth'],
          summary: 'Register a new user',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'email', 'password', 'fullName'],
                  properties: {
                    username: { type: 'string', minLength: 3, maxLength: 50 },
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', minLength: 8 },
                    fullName: { type: 'string', maxLength: 100 },
                    phone: { type: 'string' },
                    idCard: { type: 'string' },
                    bankCard: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            201: {
              description: 'User registered successfully',
              content: {
                'application/json': {
                  schema: {
                    allOf: [
                      { $ref: '#/components/schemas/AuthResponse' },
                    ],
                  },
                },
              },
            },
            400: {
              description: 'Validation error',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/ValidationError' },
                },
              },
            },
          },
        },
      },
      '/auth/login': {
        post: {
          tags: ['Auth'],
          summary: 'Login user',
          security: [],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'password'],
                  properties: {
                    username: { type: 'string' },
                    password: { type: 'string' },
                  },
                },
              },
            },
          },
          responses: {
            200: {
              description: 'Login successful',
              headers: {
                'Set-Cookie': {
                  description: 'refreshToken cookie (HTTP-only)',
                  schema: { type: 'string' },
                },
              },
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/AuthResponse' },
                },
              },
            },
            401: {
              description: 'Invalid credentials',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Error' },
                },
              },
            },
          },
        },
      },
      '/auth/refresh': {
        post: {
          tags: ['Auth'],
          summary: 'Refresh access token',
          security: [{ cookieAuth: [] }],
          responses: {
            200: {
              description: 'Token refreshed successfully',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: { type: 'string' },
                      data: {
                        type: 'object',
                        properties: {
                          accessToken: { type: 'string' },
                        },
                      },
                    },
                  },
                },
              },
            },
            401: {
              description: 'Invalid or expired refresh token',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/Error' },
                },
              },
            },
          },
        },
      },
      '/auth/logout': {
        post: {
          tags: ['Auth'],
          summary: 'Logout user',
          security: [{ bearerAuth: [] }, { csrfHeader: [] }],
          responses: {
            200: {
              description: 'Logged out successfully',
            },
          },
        },
      },
      '/auth/profile': {
        get: {
          tags: ['Auth'],
          summary: 'Get masked user profile',
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: 'Profile retrieved with masked sensitive data',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: { type: 'string' },
                      data: { $ref: '#/components/schemas/MaskedProfile' },
                    },
                  },
                },
              },
            },
          },
        },
      },
      '/auth/profile/decrypted': {
        get: {
          tags: ['Auth'],
          summary: 'Get decrypted user profile (requires additional authorization)',
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: 'Full profile with decrypted data',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      status: { type: 'string' },
                      data: {
                        type: 'object',
                        properties: {
                          phone: { type: 'string' },
                          idCard: { type: 'string' },
                          bankCard: { type: 'string' },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
  apis: [],
};

export const swaggerSpec = swaggerJsdoc(options);
