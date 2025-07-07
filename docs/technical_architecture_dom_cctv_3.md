      next();
    };
  };

  // Role-based access control
  requireRole = (roles: string | string[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      const user = (req as AuthenticatedRequest).user;
      
      if (!user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const allowedRoles = Array.isArray(roles) ? roles : [roles];
      
      if (!allowedRoles.includes(user.role)) {
        res.status(403).json({ error: 'Insufficient role permissions' });
        return;
      }

      next();
    };
  };

  // Company access control for CLIENT_USER
  requireOwnCompanyAccess = (req: Request, res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    
    if (user.role === 'CLIENT_USER') {
      // Add company filter to query parameters
      req.query.companyId = user.companyId;
    }

    next();
  };

  // Rate limiting per user
  createUserRateLimit = (windowMs: number, maxRequests: number) => {
    const userRequestCounts = new Map<string, { count: number; resetTime: number }>();

    return (req: Request, res: Response, next: NextFunction): void => {
      const user = (req as AuthenticatedRequest).user;
      
      if (!user) {
        next();
        return;
      }

      const now = Date.now();
      const userKey = user.id;
      const userLimit = userRequestCounts.get(userKey);

      if (!userLimit || now > userLimit.resetTime) {
        userRequestCounts.set(userKey, {
          count: 1,
          resetTime: now + windowMs
        });
        next();
        return;
      }

      if (userLimit.count >= maxRequests) {
        res.status(429).json({ error: 'Rate limit exceeded' });
        return;
      }

      userLimit.count++;
      next();
    };
  };

  // Check if user has specific permission (with hierarchy)
  private userHasPermission(user: AuthenticatedRequest['user'], permission: Permission): boolean {
    // Direct permission check
    if (user.permissions.includes(permission)) {
      return true;
    }

    // Permission hierarchy check
    const permissionHierarchy: Record<Permission, Permission[]> = {
      [Permission.DOWNLOAD_VIDEOS]: [Permission.VIEW_VIDEOS],
      [Permission.SEARCH_ALL_COMPANIES]: [Permission.SEARCH_OWN_COMPANY],
      [Permission.MANAGE_USERS]: [Permission.VIEW_AUDIT_LOGS],
      [Permission.GENERATE_DETAILED_REPORTS]: [Permission.GENERATE_BASIC_REPORTS],
      [Permission.SYSTEM_CONFIG]: [Permission.MANAGE_USERS, Permission.MANAGE_COMPANIES],
      // Add other hierarchies as needed
    } as any;

    // Check if user has a higher permission that includes the required one
    return user.permissions.some(userPerm => 
      permissionHierarchy[userPerm]?.includes(permission)
    );
  }

  // Password utilities
  static async hashPassword(password: string): Promise<string> {
    const rounds = parseInt(process.env.BCRYPT_ROUNDS || '12');
    return bcrypt.hash(password, rounds);
  }

  static async comparePassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  // Login attempt tracking
  async trackLoginAttempt(email: string, success: boolean, ip: string): Promise<void> {
    try {
      if (success) {
        // Reset failed attempts on successful login
        await this.prisma.user.update({
          where: { email },
          data: {
            failedLoginAttempts: 0,
            lockedUntil: null,
            lastLogin: new Date()
          }
        });
      } else {
        // Increment failed attempts
        const user = await this.prisma.user.findUnique({
          where: { email },
          select: { id: true, failedLoginAttempts: true }
        });

        if (user) {
          const newFailedAttempts = user.failedLoginAttempts + 1;
          const maxAttempts = 5;
          const lockoutDuration = 15 * 60 * 1000; // 15 minutes

          const updateData: any = {
            failedLoginAttempts: newFailedAttempts
          };

          // Lock account after max attempts
          if (newFailedAttempts >= maxAttempts) {
            updateData.lockedUntil = new Date(Date.now() + lockoutDuration);
          }

          await this.prisma.user.update({
            where: { email },
            data: updateData
          });
        }
      }

      // Log attempt for security monitoring
      logger.info('Login attempt:', {
        email,
        success,
        ip,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Error tracking login attempt:', error);
    }
  }

  // Check if account is locked
  async isAccountLocked(email: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: { lockedUntil: true }
    });

    if (!user?.lockedUntil) return false;

    return new Date() < user.lockedUntil;
  }
}
```

### **6.2 Input Validation & Sanitization**

```typescript
// src/middleware/validation.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { logger } from '../utils/logger';

// Chilean RUT validation
const chileanRUTSchema = z.string().refine((rut) => {
  const rutRegex = /^(\d{7,8})-([0-9Kk])$/;
  const match = rut.match(rutRegex);
  
  if (!match) return false;
  
  const [, number, checkDigit] = match;
  const calculatedDigit = calculateRUTCheckDigit(number);
  
  return checkDigit.toLowerCase() === calculatedDigit.toLowerCase();
}, {
  message: 'Invalid Chilean RUT format'
});

// Chilean license plate validation
const chileanLicensePlateSchema = z.string().refine((plate) => {
  const formats = {
    OLD_FORMAT: /^[A-Z]{2}[0-9]{4}$/,     // AA1234
    NEW_FORMAT: /^[A-Z]{4}[0-9]{2}$/      // ABCD12
  };
  
  return Object.values(formats).some(regex => regex.test(plate.toUpperCase()));
}, {
  message: 'Invalid Chilean license plate format'
});

// Common schemas
export const schemas = {
  // Authentication schemas
  login: z.object({
    body: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string().min(8, 'Password must be at least 8 characters')
    })
  }),

  register: z.object({
    body: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
               'Password must contain uppercase, lowercase, number and special character'),
      firstName: z.string().min(2, 'First name must be at least 2 characters').max(50),
      lastName: z.string().min(2, 'Last name must be at least 2 characters').max(50),
      phone: z.string().optional(),
      companyId: z.string().uuid().optional()
    })
  }),

  // Company schemas
  createCompany: z.object({
    body: z.object({
      rut: chileanRUTSchema,
      name: z.string().min(2, 'Company name must be at least 2 characters').max(200),
      businessName: z.string().max(200).optional(),
      address: z.string().min(5, 'Address must be at least 5 characters').max(300),
      city: z.string().min(2, 'City must be at least 2 characters').max(100),
      region: z.string().min(2, 'Region must be at least 2 characters').max(100),
      phone: z.string().regex(/^\+?[\d\s-()]+$/, 'Invalid phone format'),
      email: z.string().email('Invalid email format'),
      primaryContact: z.object({
        name: z.string().min(2, 'Contact name must be at least 2 characters').max(100),
        position: z.string().min(2, 'Position must be at least 2 characters').max(100),
        phone: z.string().regex(/^\+?[\d\s-()]+$/, 'Invalid phone format'),
        email: z.string().email('Invalid contact email format')
      })
    })
  }),

  updateCompany: z.object({
    params: z.object({
      id: z.string().uuid('Invalid company ID format')
    }),
    body: z.object({
      name: z.string().min(2).max(200).optional(),
      businessName: z.string().max(200).optional(),
      address: z.string().min(5).max(300).optional(),
      city: z.string().min(2).max(100).optional(),
      region: z.string().min(2).max(100).optional(),
      phone: z.string().regex(/^\+?[\d\s-()]+$/).optional(),
      email: z.string().email().optional(),
      isActive: z.boolean().optional(),
      primaryContact: z.object({
        name: z.string().min(2).max(100),
        position: z.string().min(2).max(100),
        phone: z.string().regex(/^\+?[\d\s-()]+$/),
        email: z.string().email()
      }).optional()
    })
  }),

  // Event schemas
  createEvent: z.object({
    body: z.object({
      licensePlate: chileanLicensePlateSchema,
      eventDateTime: z.string().datetime('Invalid datetime format'),
      confidence: z.number().min(0, 'Confidence must be at least 0').max(100, 'Confidence cannot exceed 100'),
      companyId: z.string().uuid('Invalid company ID format'),
      primaryCamera: z.object({
        id: z.string().min(1, 'Camera ID is required'),
        image: z.string().url('Invalid image URL'),
        confidence: z.number().min(0).max(100),
        plateReading: z.string().min(1, 'Plate reading is required')
      }),
      secondaryCamera: z.object({
        id: z.string().min(1),
        image: z.string().url(),
        confidence: z.number().min(0).max(100),
        plateReading: z.string().min(1)
      }).optional(),
      documentaryVideos: z.array(z.object({
        cameraId: z.string().min(1, 'Camera ID is required'),
        filename: z.string().min(1, 'Filename is required'),
        duration: z.number().min(0, 'Duration must be positive'),
        size: z.number().min(0, 'Size must be positive')
      }))
    })
  }),

  searchEvents: z.object({
    query: z.object({
      licensePlate: z.string().optional(),
      companyId: z.string().uuid().optional(),
      startDate: z.string().datetime().optional(),
      endDate: z.string().datetime().optional(),
      status: z.enum(['DETECTED', 'DOCUMENTED', 'VALIDATED', 'ARCHIVED']).optional(),
      hasMetadata: z.string().transform(val => val === 'true').optional(),
      page: z.string().regex(/^\d+$/).transform(Number).optional(),
      limit: z.string().regex(/^\d+$/).transform(Number).refine(val => val <= 100, 'Limit cannot exceed 100').optional()
    })
  }),

  // Metadata schemas
  createMetadata: z.object({
    params: z.object({
      eventId: z.string().uuid('Invalid event ID format')
    }),
    body: z.object({
      basicReturnInfo: z.object({
        guideNumber: z.string().max(50).optional(),
        guideDate: z.string().datetime().optional(),
        originProject: z.string().max(200).optional(),
        cargoDescription: z.string().max(500).optional(),
        observations: z.string().max(1000).optional()
      })
    })
  }),

  // User schemas
  createUser: z.object({
    body: z.object({
      email: z.string().email('Invalid email format'),
      password: z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, 
               'Password must be strong'),
      firstName: z.string().min(2).max(50),
      lastName: z.string().min(2).max(50),
      role: z.enum(['ADMINISTRATOR', 'SUPERVISOR', 'OPERATOR', 'CLIENT_USER']),
      companyId: z.string().uuid().optional(),
      department: z.string().max(100).optional(),
      position: z.string().max(100).optional()
    })
  }),

  updateUser: z.object({
    params: z.object({
      id: z.string().uuid('Invalid user ID format')
    }),
    body: z.object({
      firstName: z.string().min(2).max(50).optional(),
      lastName: z.string().min(2).max(50).optional(),
      phone: z.string().regex(/^\+?[\d\s-()]+$/).optional(),
      department: z.string().max(100).optional(),
      position: z.string().max(100).optional(),
      isActive: z.boolean().optional()
    })
  }),

  // Video schemas
  videoDownload: z.object({
    params: z.object({
      eventId: z.string().uuid('Invalid event ID format')
    }),
    query: z.object({
      cameraId: z.string().min(1, 'Camera ID is required'),
      quality: z.enum(['high', 'medium', 'low']).default('high'),
      startTime: z.string().datetime().optional(),
      endTime: z.string().datetime().optional()
    })
  })
};

// Validation middleware factory
export const validate = (schema: z.ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const result = schema.parse({
        body: req.body,
        query: req.query,
        params: req.params
      });

      // Replace request objects with validated/transformed data
      req.body = result.body || req.body;
      req.query = result.query || req.query;
      req.params = result.params || req.params;

      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code
        }));

        logger.warn('Validation failed:', { errors, url: req.url, method: req.method });

        res.status(400).json({
          error: 'Validation failed',
          details: errors
        });
      } else {
        logger.error('Unexpected validation error:', error);
        res.status(500).json({ error: 'Internal validation error' });
      }
    }
  };
};

// Input sanitization middleware
export const sanitizeInput = (req: Request, res: Response, next: NextFunction): void => {
  // Recursively sanitize object
  const sanitize = (obj: any): any => {
    if (typeof obj === 'string') {
      // Remove potentially dangerous characters
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
    }
    
    if (Array.isArray(obj)) {
      return obj.map(sanitize);
    }
    
    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitize(value);
      }
      return sanitized;
    }
    
    return obj;
  };

  req.body = sanitize(req.body);
  req.query = sanitize(req.query);
  next();
};

// RUT check digit calculation helper
function calculateRUTCheckDigit(rut: string): string {
  let sum = 0;
  let multiplier = 2;
  
  for (let i = rut.length - 1; i >= 0; i--) {
    sum += parseInt(rut[i]) * multiplier;
    multiplier = multiplier === 7 ? 2 : multiplier + 1;
  }
  
  const remainder = sum % 11;
  const checkDigit = 11 - remainder;
  
  if (checkDigit === 11) return '0';
  if (checkDigit === 10) return 'K';
  return checkDigit.toString();
}
```

### **6.3 Security Headers & CORS**

```typescript
// src/middleware/security.middleware.ts
import helmet from 'helmet';
import cors from 'cors';
import { Request, Response, NextFunction } from 'express';

// CORS configuration
export const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || ['http://localhost:5173'];
    
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-Total-Count', 'X-Current-Page']
};

// Security headers configuration
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "wss:", "ws:"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false, // Disable for video streaming
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Request logging for security monitoring
export const securityLogger = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log suspicious activity
    if (
      res.statusCode === 401 || 
      res.statusCode === 403 || 
      duration > 10000 || // Very slow requests
      req.url.includes('admin') ||
      req.url.includes('config')
    ) {
      console.log({
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        status: res.statusCode,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        duration,
        suspicious: true
      });
    }
  });
  
  next();
};

// IP-based rate limiting
const ipRequestCounts = new Map<string, { count: number; resetTime: number }>();

export const ipRateLimit = (windowMs: number, maxRequests: number) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip;
    const now = Date.now();
    const ipLimit = ipRequestCounts.get(ip);

    if (!ipLimit || now > ipLimit.resetTime) {
      ipRequestCounts.set(ip, {
        count: 1,
        resetTime: now + windowMs
      });
      next();
      return;
    }

    if (ipLimit.count >= maxRequests) {
      res.status(429).json({ 
        error: 'Too many requests from this IP',
        retryAfter: Math.ceil((ipLimit.resetTime - now) / 1000)
      });
      return;
    }

    ipLimit.count++;
    next();
  };
};

// Block common attack patterns
export const blockMaliciousRequests = (req: Request, res: Response, next: NextFunction): void => {
  const suspiciousPatterns = [
    /\.\.\//, // Directory traversal
    /<script/i, // XSS attempts
    /union.*select/i, // SQL injection
    /javascript:/i, // JavaScript injection
    /eval\(/i, // Code injection
    /base64_decode/i, // PHP injection
    /cmd\.exe/i, // Command injection
    /\/etc\/passwd/, // Unix system file access
    /\/proc\//, // Linux proc access
    /\\x[0-9a-f]{2}/i // Encoded characters
  ];

  const url = req.url.toLowerCase();
  const body = JSON.stringify(req.body).toLowerCase();
  const query = JSON.stringify(req.query).toLowerCase();

  const isSuspicious = suspiciousPatterns.some(pattern => 
    pattern.test(url) || pattern.test(body) || pattern.test(query)
  );

  if (isSuspicious) {
    console.log({
      type: 'BLOCKED_MALICIOUS_REQUEST',
      timestamp: new Date().toISOString(),
      ip: req.ip,
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      body: req.body,
      query: req.query
    });

    res.status(400).json({ error: 'Request blocked for security reasons' });
    return;
  }

  next();
};
```

---

## 📚 **7. TESTING STRATEGY IMPLEMENTATION**

### **7.1 Backend Unit Tests**

```typescript
// tests/unit/services/events.service.test.ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { PrismaClient } from '@prisma/client';
import { mockDeep, mockReset, DeepMockProxy } from 'vitest-mock-extended';
import { EventsService } from '../../../src/services/events.service';
import { HikCentralClient } from '../../../src/integrations/hikvision/hikcentral.client';

// Mock Prisma client
vi.mock('../../../src/models/database', () => ({
  prisma: mockDeep<PrismaClient>()
}));

// Mock Hikvision client
vi.mock('../../../src/integrations/hikvision/hikcentral.client');

describe('EventsService', () => {
  let eventsService: EventsService;
  let mockPrisma: DeepMockProxy<PrismaClient>;
  let mockHikCentral: DeepMockProxy<HikCentralClient>;

  beforeEach(() => {
    mockPrisma = mockDeep<PrismaClient>();
    mockHikCentral = mockDeep<HikCentralClient>();
    eventsService = new EventsService(mockPrisma, mockHikCentral);
  });

  afterEach(() => {
    mockReset(mockPrisma);
    mockReset(mockHikCentral);
  });

  describe('searchEvents', () => {
    it('should return paginated events with correct filters', async () => {
      // Arrange
      const mockEvents = [
        {
          id: '1',
          licensePlate: 'ABC123',
          eventDateTime: new Date(),
          confidence: 95,
          companyId: 'company-1',
          company: { id: 'company-1', name: 'Test Company', rut: '12345678-9' },
          basicMetadata: null
        }
      ];

      mockPrisma.event.findMany.mockResolvedValue(mockEvents);
      mockPrisma.event.count.mockResolvedValue(1);

      // Act
      const result = await eventsService.searchEvents({
        licensePlate: 'ABC',
        page: 1,
        limit: 25
      });

      // Assert
      expect(result.events).toHaveLength(1);
      expect(result.total).toBe(1);
      expect(result.page).toBe(1);
      expect(mockPrisma.event.findMany).toHaveBeenCalledWith({
        where: {
          licensePlate: { contains: 'ABC' }
        },
        include: {
          company: {
            select: { id: true, name: true, rut: true }
          },
          basicMetadata: {
            select: {
              id: true,
              basicReturnInfo: true,
              readyForDetailedProcessing: true
            }
          }
        },
        orderBy: { eventDateTime: 'desc' },
        skip: 0,
        take: 25
      });
    });

    it('should filter by company for CLIENT_USER', async () => {
      // Arrange
      mockPrisma.event.findMany.mockResolvedValue([]);
      mockPrisma.event.count.mockResolvedValue(0);

      // Act
      await eventsService.searchEvents({}, 'company-1');

      // Assert
      expect(mockPrisma.event.findMany).toHaveBeenCalledWith({
        where: { companyId: 'company-1' },
        include: expect.any(Object),
        orderBy: { eventDateTime: 'desc' },
        skip: 0,
        take: 25
      });
    });

    it('should handle search errors gracefully', async () => {
      // Arrange
      mockPrisma.event.findMany.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(eventsService.searchEvents({})).rejects.toThrow('Failed to search events');
    });
  });

  describe('createEvent', () => {
    it('should create event with valid data', async () => {
      // Arrange
      const mockCompany = { id: 'company-1', name: 'Test Company' };
      const mockEvent = {
        id: 'event-1',
        licensePlate: 'ABC123',
        eventDateTime: new Date(),
        confidence: 95,
        companyId: 'company-1',
        company: mockCompany
      };

      mockPrisma.company.findUnique.mockResolvedValue(mockCompany as any);
      mockPrisma.event.create.mockResolvedValue(mockEvent as any);

      const eventData = {
        licensePlate: 'abc123',
        eventDateTime: new Date(),
        confidence: 95,
        companyId: 'company-1',
        primaryCamera: {
          id: 'camera-1',
          image: 'http://example.com/image.jpg',
          confidence: 95,
          plateReading: 'ABC123'
        },
        documentaryVideos: [],
        createdBy: 'user-1'
      };

      // Act
      const result = await eventsService.createEvent(eventData);

      // Assert
      expect(result.licensePlate).toBe('ABC123'); // Should be uppercase
      expect(mockPrisma.company.findUnique).toHaveBeenCalledWith({
        where: { id: 'company-1' }
      });
      expect(mockPrisma.event.create).toHaveBeenCalledWith({
        data: {
          licensePlate: 'ABC123',
          eventDateTime: eventData.eventDateTime,
          confidence: 95,
          companyId: 'company-1',
          primaryCamera: eventData.primaryCamera,
          secondaryCamera: null,
          status: 'DETECTED',
          hasBasicMetadata: false,
          readyForPhase2: false,
          documentaryVideos: [],
          createdBy: 'user-1'
        },
        include: { company: true }
      });
    });

    it('should throw error for non-existent company', async () => {
      // Arrange
      mockPrisma.company.findUnique.mockResolvedValue(null);

      const eventData = {
        licensePlate: 'ABC123',
        eventDateTime: new Date(),
        confidence: 95,
        companyId: 'non-existent',
        primaryCamera: {
          id: 'camera-1',
          image: 'http://example.com/image.jpg',
          confidence: 95,
          plateReading: 'ABC123'
        },
        documentaryVideos: [],
        createdBy: 'user-1'
      };

      // Act & Assert
      await expect(eventsService.createEvent(eventData)).rejects.toThrow('Company not found');
    });
  });

  describe('syncFromHikvision', () => {
    it('should sync new events from Hikvision', async () => {
      // Arrange
      const mockANPREvents = [
        {
          plateNumber: 'ABC123',
          confidence: 95,
          captureTime: '2025-07-07T12:00:00Z',
          cameraIndexCode: 'camera-1',
          picUri: 'http://example.com/pic.jpg'
        }
      ];

      mockHikCentral.searchANPREvents.mockResolvedValue(mockANPREvents);
      mockPrisma.event.findFirst.mockResolvedValue(null); // No existing event
      mockPrisma.company.findUnique.mockResolvedValue({ id: 'company-1' } as any);
      mockPrisma.event.create.mockResolvedValue({ id: 'event-1' } as any);

      // Mock the company matching method
      vi.spyOn(eventsService as any, 'matchCompanyByLicensePlate').mockResolvedValue('company-1');

      // Act
      const result = await eventsService.syncFromHikv    volumes:
      - ./backend:/app/backend
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    depends_on:
      - mysql
      - redis
    restart: unless-stopped
    networks:
      - dom_cctv_network

  # Frontend Development Server
  frontend:
    build:
      context: .
      dockerfile: Dockerfile
      target: frontend-builder
    container_name: dom_cctv_frontend
    environment:
      NODE_ENV: development
      VITE_API_BASE_URL: http://localhost:3000/api
      VITE_WS_URL: ws://localhost:3000
    ports:
      - "5173:5173"
    volumes:
      - ./frontend:/app/frontend
    depends_on:
      - backend
    restart: unless-stopped
    networks:
      - dom_cctv_network

  # Nginx Reverse Proxy
  nginx:
    image: nginx:alpine
    container_name: dom_cctv_nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
      - ./uploads:/var/www/uploads
    depends_on:
      - backend
      - frontend
    restart: unless-stopped
    networks:
      - dom_cctv_network

volumes:
  mysql_data:
  redis_data:

networks:
  dom_cctv_network:
    driver: bridge
```

### **4.2 Nginx Configuration**

```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                   '$status $body_bytes_sent "$http_referer" '
                   '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

    # Upstream servers
    upstream backend {
        server backend:3000;
    }

    upstream frontend {
        server frontend:5173;
    }

    # HTTP Server (redirect to HTTPS in production)
    server {
        listen 80;
        server_name localhost dom-cctv.local;

        # Development: serve directly
        # Production: redirect to HTTPS
        # return 301 https://$server_name$request_uri;

        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # API routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # CORS headers
            add_header Access-Control-Allow-Origin *;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS";
            add_header Access-Control-Allow-Headers "Content-Type, Authorization";
        }

        # Auth routes with stricter rate limiting
        location /api/auth/login {
            limit_req zone=login burst=3 nodelay;
            
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Video streaming
        location /api/video/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Video streaming optimizations
            proxy_buffering off;
            proxy_cache off;
            proxy_read_timeout 300s;
            proxy_connect_timeout 75s;
        }

        # Static file serving
        location /uploads/ {
            alias /var/www/uploads/;
            expires 1y;
            add_header Cache-Control "public, immutable";
            
            # Security headers for file access
            add_header X-Content-Type-Options nosniff;
            add_header X-Frame-Options DENY;
        }

        # Health check
        location /health {
            proxy_pass http://backend/health;
            access_log off;
        }
    }

    # HTTPS Server (Production)
    server {
        listen 443 ssl http2;
        server_name dom-cctv.local;

        # SSL Configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header Strict-Transport-Security "max-age=63072000" always;
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        # Same location blocks as HTTP server
        location / {
            proxy_pass http://frontend;
            # ... same config as HTTP
        }

        # ... other location blocks
    }
}
```

### **4.3 Environment Variables Configuration**

```bash
# .env.example
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=dom_cctv
DB_USER=dom_user
DB_PASSWORD=secure_password_here
DB_ROOT_PASSWORD=root_password_here
DATABASE_URL="mysql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_URL="redis://${REDIS_HOST}:${REDIS_PORT}"

# JWT Configuration
JWT_SECRET=your_very_secure_jwt_secret_here_at_least_32_characters
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Hikvision Integration
HIKVISION_BASE_URL=https://your-hikvision-server.com
HIKVISION_USERNAME=your_hikvision_user
HIKVISION_PASSWORD=your_hikvision_password
HIKVISION_TIMEOUT=30000

# Video Configuration
VIDEO_STORAGE_PATH=/app/uploads/videos
THUMBNAIL_STORAGE_PATH=/app/uploads/thumbnails
MAX_VIDEO_SIZE=500MB
SUPPORTED_VIDEO_FORMATS=mp4,avi,mov,mkv

# ANPR Configuration
ANPR_CONFIDENCE_THRESHOLD=85
ANPR_CALLBACK_URL=http://your-domain.com/api/webhooks/anpr
AUTO_SYNC_INTERVAL=300000

# Security Configuration
BCRYPT_ROUNDS=12
SESSION_SECRET=your_session_secret_here
CORS_ORIGIN=http://localhost:5173
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# Email Configuration (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
FROM_EMAIL=noreply@dom-cctv.com

# File Upload Configuration
MAX_FILE_SIZE=50MB
ALLOWED_IMAGE_TYPES=jpg,jpeg,png,gif
TEMP_UPLOAD_PATH=/app/uploads/temp

# Logging Configuration
LOG_LEVEL=info
LOG_FILE_PATH=/app/logs
LOG_MAX_SIZE=10MB
LOG_MAX_FILES=5

# Performance Configuration
CACHE_TTL=3600
DB_POOL_MIN=2
DB_POOL_MAX=10
COMPRESSION_ENABLED=true

# Development Configuration
NODE_ENV=development
PORT=3000
HOST=0.0.0.0

# Frontend Configuration
VITE_API_BASE_URL=http://localhost:3000/api
VITE_WS_URL=ws://localhost:3000
VITE_VIDEO_STREAM_URL=http://localhost:3000/api/video
VITE_UPLOAD_MAX_SIZE=50MB
VITE_SENTRY_DSN=your_sentry_dsn_here

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_INTERVAL=30000

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_SCHEDULE="0 2 * * *"
BACKUP_RETENTION_DAYS=30
BACKUP_STORAGE_PATH=/app/backups
```

### **4.4 CI/CD Pipeline Configuration**

```yaml
# .github/workflows/deploy.yml
name: DOM CCTV Deployment

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: dom-cctv

jobs:
  # Testing Job
  test:
    runs-on: ubuntu-latest
    
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: root
          MYSQL_DATABASE: test_dom_cctv
        options: >-
          --health-cmd="mysqladmin ping"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=3
        ports:
          - 3306:3306

      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd="redis-cli ping"
          --health-interval=10s
          --health-timeout=5s
          --health-retries=3
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v4

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: 'npm'
        cache-dependency-path: |
          backend/package-lock.json
          frontend/package-lock.json

    # Backend Tests
    - name: Install Backend Dependencies
      working-directory: ./backend
      run: npm ci

    - name: Run Database Migrations
      working-directory: ./backend
      run: |
        npx prisma generate
        npx prisma db push
      env:
        DATABASE_URL: mysql://root:root@localhost:3306/test_dom_cctv

    - name: Run Backend Tests
      working-directory: ./backend
      run: npm test
      env:
        NODE_ENV: test
        DATABASE_URL: mysql://root:root@localhost:3306/test_dom_cctv
        REDIS_URL: redis://localhost:6379
        JWT_SECRET: test_secret

    # Frontend Tests
    - name: Install Frontend Dependencies
      working-directory: ./frontend
      run: npm ci

    - name: Run Frontend Tests
      working-directory: ./frontend
      run: npm test

    - name: Build Frontend
      working-directory: ./frontend
      run: npm run build

    # Code Quality
    - name: Run ESLint
      working-directory: ./backend
      run: npm run lint

    - name: Run TypeScript Check
      working-directory: ./backend
      run: npm run type-check

  # Security Scan
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Security Audit
      run: |
        cd backend && npm audit --audit-level moderate
        cd ../frontend && npm audit --audit-level moderate

    - name: Run Snyk Security Scan
      uses: snyk/actions/node@master
      env:
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

  # Build and Push Docker Image
  build:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
    - uses: actions/checkout@v4

    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3

    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}

    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ github.repository }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=sha,prefix={{branch}}-
          type=raw,value=latest,enable={{is_default_branch}}

    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  # Deploy to Production
  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
    - name: Deploy to Server
      uses: appleboy/ssh-action@v1.0.0
      with:
        host: ${{ secrets.PRODUCTION_HOST }}
        username: ${{ secrets.PRODUCTION_USER }}
        key: ${{ secrets.PRODUCTION_SSH_KEY }}
        script: |
          cd /opt/dom-cctv
          docker-compose down
          docker-compose pull
          docker-compose up -d
          docker system prune -f

    - name: Health Check
      run: |
        sleep 30
        curl -f ${{ secrets.PRODUCTION_URL }}/health || exit 1

  # Deploy to Staging
  deploy-staging:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop'
    environment: staging

    steps:
    - name: Deploy to Staging Server
      uses: appleboy/ssh-action@v1.0.0
      with:
        host: ${{ secrets.STAGING_HOST }}
        username: ${{ secrets.STAGING_USER }}
        key: ${{ secrets.STAGING_SSH_KEY }}
        script: |
          cd /opt/dom-cctv-staging
          git pull origin develop
          docker-compose down
          docker-compose build
          docker-compose up -d
```

---

## 📊 **5. MONITORING & OBSERVABILITY**

### **5.1 Application Monitoring Setup**

```typescript
// src/utils/monitoring.ts
import { Request, Response, NextFunction } from 'express';
import { logger } from './logger';

interface MetricsData {
  timestamp: number;
  method: string;
  route: string;
  statusCode: number;
  responseTime: number;
  userAgent?: string;
  ip?: string;
  userId?: string;
  companyId?: string;
}

class MetricsCollector {
  private metrics: MetricsData[] = [];
  private readonly maxMetrics = 1000;

  collect(data: MetricsData): void {
    this.metrics.push(data);
    
    if (this.metrics.length > this.maxMetrics) {
      this.metrics = this.metrics.slice(-this.maxMetrics);
    }
  }

  getMetrics(): MetricsData[] {
    return [...this.metrics];
  }

  getAverageResponseTime(route?: string): number {
    const filteredMetrics = route 
      ? this.metrics.filter(m => m.route === route)
      : this.metrics;

    if (filteredMetrics.length === 0) return 0;

    const total = filteredMetrics.reduce((sum, m) => sum + m.responseTime, 0);
    return total / filteredMetrics.length;
  }

  getErrorRate(timeWindow: number = 3600000): number {
    const now = Date.now();
    const recent = this.metrics.filter(m => now - m.timestamp < timeWindow);
    
    if (recent.length === 0) return 0;

    const errors = recent.filter(m => m.statusCode >= 400);
    return (errors.length / recent.length) * 100;
  }

  getThroughput(timeWindow: number = 3600000): number {
    const now = Date.now();
    const recent = this.metrics.filter(m => now - m.timestamp < timeWindow);
    
    return recent.length / (timeWindow / 1000); // requests per second
  }
}

export const metricsCollector = new MetricsCollector();

// Middleware to collect metrics
export const metricsMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  const startTime = Date.now();

  res.on('finish', () => {
    const responseTime = Date.now() - startTime;
    
    metricsCollector.collect({
      timestamp: startTime,
      method: req.method,
      route: req.route?.path || req.path,
      statusCode: res.statusCode,
      responseTime,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: (req as any).user?.id,
      companyId: (req as any).user?.companyId
    });

    // Log slow requests
    if (responseTime > 2000) {
      logger.warn('Slow request detected:', {
        method: req.method,
        route: req.path,
        responseTime,
        userId: (req as any).user?.id
      });
    }
  });

  next();
};

// Health check endpoint
export const healthCheck = (req: Request, res: Response): void => {
  const metrics = metricsCollector.getMetrics();
  const avgResponseTime = metricsCollector.getAverageResponseTime();
  const errorRate = metricsCollector.getErrorRate();
  const throughput = metricsCollector.getThroughput();

  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    metrics: {
      averageResponseTime: Math.round(avgResponseTime),
      errorRate: Math.round(errorRate * 100) / 100,
      throughput: Math.round(throughput * 100) / 100,
      totalRequests: metrics.length
    },
    database: {
      connected: true, // Should check actual DB connection
      responseTime: 0  // Should measure actual DB query time
    },
    external: {
      hikvision: {
        connected: true, // Should check actual Hikvision connection
        lastSync: new Date().toISOString()
      }
    }
  };

  // Determine overall health status
  if (avgResponseTime > 5000 || errorRate > 10) {
    health.status = 'degraded';
  }

  if (avgResponseTime > 10000 || errorRate > 25) {
    health.status = 'unhealthy';
  }

  res.status(health.status === 'healthy' ? 200 : 503).json(health);
};
```

### **5.2 Business Metrics Dashboard**

```typescript
// src/services/business-metrics.service.ts
interface BusinessMetrics {
  events: {
    total: number;
    today: number;
    documented: number;
    pending: number;
    documentationRate: number;
  };
  performance: {
    avgSearchTime: number;
    avgVideoLoadTime: number;
    systemUptime: number;
    anprAccuracy: number;
  };
  companies: {
    active: number;
    totalEvents: number;
    topCompanies: Array<{
      id: string;
      name: string;
      eventCount: number;
    }>;
  };
  users: {
    active: number;
    totalSessions: number;
    avgSessionDuration: number;
  };
}

export class BusinessMetricsService {
  constructor(private prisma: PrismaClient) {}

  async getBusinessMetrics(): Promise<BusinessMetrics> {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    
    // Events metrics
    const [
      totalEvents,
      todayEvents,
      documentedEvents,
      pendingEvents,
      topCompanies
    ] = await Promise.all([
      this.prisma.event.count(),
      this.prisma.event.count({
        where: { eventDateTime: { gte: today } }
      }),
      this.prisma.event.count({
        where: { hasBasicMetadata: true }
      }),
      this.prisma.event.count({
        where: { hasBasicMetadata: false }
      }),
      this.prisma.event.groupBy({
        by: ['companyId'],
        _count: { id: true },
        orderBy: { _count: { id: 'desc' } },
        take: 5,
        include: {
          company: {
            select: { id: true, name: true }
          }
        }
      })
    ]);

    // Performance metrics (from metrics collector)
    const avgSearchTime = metricsCollector.getAverageResponseTime('/api/events');
    const avgVideoLoadTime = metricsCollector.getAverageResponseTime('/api/video');
    
    // Companies metrics
    const activeCompanies = await this.prisma.company.count({
      where: { isActive: true }
    });

    // Users metrics
    const activeUsers = await this.prisma.user.count({
      where: { isActive: true }
    });

    return {
      events: {
        total: totalEvents,
        today: todayEvents,
        documented: documentedEvents,
        pending: pendingEvents,
        documentationRate: totalEvents > 0 ? (documentedEvents / totalEvents) * 100 : 0
      },
      performance: {
        avgSearchTime: Math.round(avgSearchTime),
        avgVideoLoadTime: Math.round(avgVideoLoadTime),
        systemUptime: Math.round(process.uptime()),
        anprAccuracy: 92.5 // This should come from actual ANPR analytics
      },
      companies: {
        active: activeCompanies,
        totalEvents: totalEvents,
        topCompanies: topCompanies.map(tc => ({
          id: tc.companyId,
          name: tc.company?.name || 'Unknown',
          eventCount: tc._count.id
        }))
      },
      users: {
        active: activeUsers,
        totalSessions: 0, // Implement session tracking
        avgSessionDuration: 0 // Implement session duration tracking
      }
    };
  }

  async getPerformanceMetrics(timeWindow: string = '1h'): Promise<any> {
    const windowMs = this.parseTimeWindow(timeWindow);
    const now = Date.now();
    const startTime = now - windowMs;

    const metrics = metricsCollector.getMetrics()
      .filter(m => m.timestamp >= startTime);

    // Group by time intervals (5-minute buckets)
    const bucketSize = 5 * 60 * 1000; // 5 minutes
    const buckets = new Map();

    metrics.forEach(metric => {
      const bucket = Math.floor(metric.timestamp / bucketSize) * bucketSize;
      if (!buckets.has(bucket)) {
        buckets.set(bucket, {
          timestamp: bucket,
          requests: 0,
          avgResponseTime: 0,
          errors: 0,
          responseTimes: []
        });
      }

      const data = buckets.get(bucket);
      data.requests++;
      data.responseTimes.push(metric.responseTime);
      if (metric.statusCode >= 400) data.errors++;
    });

    // Calculate averages
    const result = Array.from(buckets.values()).map(bucket => ({
      timestamp: bucket.timestamp,
      requests: bucket.requests,
      avgResponseTime: bucket.responseTimes.length > 0
        ? bucket.responseTimes.reduce((a, b) => a + b, 0) / bucket.responseTimes.length
        : 0,
      errorRate: bucket.requests > 0 ? (bucket.errors / bucket.requests) * 100 : 0,
      p95ResponseTime: this.calculatePercentile(bucket.responseTimes, 95),
      p99ResponseTime: this.calculatePercentile(bucket.responseTimes, 99)
    }));

    return result.sort((a, b) => a.timestamp - b.timestamp);
  }

  private parseTimeWindow(window: string): number {
    const value = parseInt(window);
    const unit = window.slice(-1);

    switch (unit) {
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      case 'd': return value * 24 * 60 * 60 * 1000;
      default: return 60 * 60 * 1000; // 1 hour default
    }
  }

  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) return 0;
    
    const sorted = values.sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    
    return sorted[Math.max(0, index)];
  }
}
```

---

## 🔐 **6. SECURITY IMPLEMENTATION**

### **6.1 Authentication & Authorization**

```typescript
// src/middleware/auth.middleware.ts
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { Request, Response, NextFunction } from 'express';
import { PrismaClient, User, Permission } from '../types/generated';
import { logger } from '../utils/logger';

interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  companyId?: string;
  permissions: Permission[];
  iat: number;
  exp: number;
}

interface AuthenticatedRequest extends Request {
  user: {
    id: string;
    email: string;
    role: string;
    companyId?: string;
    permissions: Permission[];
  };
}

export class AuthMiddleware {
  constructor(private prisma: PrismaClient) {}

  // JWT Token generation
  generateTokens(user: User, permissions: Permission[]): { accessToken: string; refreshToken: string } {
    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
      companyId: user.companyId,
      permissions
    };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET!, {
      expiresIn: process.env.JWT_EXPIRES_IN || '24h'
    });

    const refreshToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET!,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    return { accessToken, refreshToken };
  }

  // Verify JWT token middleware
  verifyToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Access token required' });
        return;
      }

      const token = authHeader.substring(7);
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;

      // Verify user still exists and is active
      const user = await this.prisma.user.findUnique({
        where: { id: payload.userId },
        include: {
          permissions: true,
          company: {
            select: { id: true, isActive: true }
          }
        }
      });

      if (!user || !user.isActive) {
        res.status(401).json({ error: 'User not found or inactive' });
        return;
      }

      // Check if user's company is still active (for CLIENT_USER)
      if (user.companyId && (!user.company || !user.company.isActive)) {
        res.status(401).json({ error: 'Company is inactive' });
        return;
      }

      // Attach user info to request
      (req as AuthenticatedRequest).user = {
        id: user.id,
        email: user.email,
        role: user.role,
        companyId: user.companyId || undefined,
        permissions: user.permissions.map(p => p.permission)
      };

      next();
    } catch (error) {
      logger.error('Token verification failed:', error);
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  // Permission check middleware
  requirePermission = (requiredPermissions: Permission | Permission[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      const user = (req as AuthenticatedRequest).user;
      
      if (!user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const permissions = Array.isArray(requiredPermissions) 
        ? requiredPermissions 
        : [requiredPermissions];

      const hasPermission = permissions.some(permission => 
        this.userHasPermission(user, permission)
      );

      if (!hasPermission) {
        res.status(403).json({ error: 'Insufficient permissions' });
        return;
      }# Technical Architecture Document - DOM CCTV
## Context Engineering Implementation Guide

### **Metadatos del Documento**
- **Versión:** 1.0 - Context Engineering Ready
- **Fecha:** 07/07/2025
- **Metodología:** Context Engineering Optimized
- **Basado en:** PRD DOM CCTV v2.0
- **Target:** Desarrollo con Claude Code + AI Tools

---

## 🏗️ **1. ARQUITECTURA GENERAL DEL SISTEMA**

### **1.1 Stack Tecnológico Definitivo**

```typescript
// Technology Stack - Production Ready
interface TechStack {
  backend: {
    runtime: 'Node.js 18 LTS';
    language: 'TypeScript 5.0+';
    framework: 'Express.js 4.18+';
    orm: 'Prisma 5.0+';
    validation: 'Zod 3.21+';
    auth: 'jsonwebtoken + bcrypt';
  };
  
  frontend: {
    framework: 'React 18.2+';
    language: 'TypeScript 5.0+';
    bundler: 'Vite 4.4+';
    ui: 'Material-UI (MUI) 5.14+';
    stateManagement: 'Zustand 4.4+';
    serverState: 'TanStack Query 4.32+';
    forms: 'React Hook Form 7.45+';
  };
  
  database: {
    primary: 'MySQL 8.0+';
    orm: 'Prisma Client';
    cache: 'Redis 7.0+ (production)';
    search: 'MySQL Full-Text Search';
  };
  
  external: {
    cctv: 'Hikvision APIs (HikCentral + ISAPI)';
    streaming: 'RTSP + HTTP Proxy';
    storage: 'Local NFS + Cloud Backup';
  };
  
  deployment: {
    containerization: 'Docker + Docker Compose';
    webServer: 'Nginx (reverse proxy)';
    ssl: 'Let\'s Encrypt';
    monitoring: 'PM2 + Custom Dashboards';
  };
}
```

### **1.2 Arquitectura por Capas**

```mermaid
graph TB
    subgraph "Frontend Layer"
        UI[React + Material UI]
        State[Zustand + TanStack Query]
    end
    
    subgraph "API Gateway Layer"
        Nginx[Nginx Reverse Proxy]
        Auth[JWT Middleware]
    end
    
    subgraph "Application Layer"
        API[Express.js REST API]
        Services[Business Logic Services]
        Controllers[Route Controllers]
    end
    
    subgraph "Integration Layer"
        HikAPI[Hikvision API Client]
        VideoProxy[Video Stream Proxy]
    end
    
    subgraph "Data Layer"
        Prisma[Prisma ORM]
        MySQL[MySQL 8.0 Partitioned]
        Redis[Redis Cache]
    end
    
    subgraph "External Systems"
        HikCentral[HikCentral Professional]
        Cameras[IP Cameras ISAPI]
        Storage[Video File Storage]
    end
    
    UI --> Nginx
    Nginx --> Auth
    Auth --> API
    API --> Services
    Services --> Controllers
    Services --> HikAPI
    Services --> VideoProxy
    Services --> Prisma
    Prisma --> MySQL
    Services --> Redis
    HikAPI --> HikCentral
    VideoProxy --> Cameras
    VideoProxy --> Storage
```

---

## 🔧 **2. BACKEND ARCHITECTURE DETALLADA**

### **2.1 Estructura de Directorios**

```
backend/
├── src/
│   ├── controllers/           # Route handlers (thin layer)
│   │   ├── auth.controller.ts
│   │   ├── events.controller.ts
│   │   ├── companies.controller.ts
│   │   ├── users.controller.ts
│   │   └── videos.controller.ts
│   │
│   ├── services/              # Business logic (thick layer)
│   │   ├── auth.service.ts
│   │   ├── events.service.ts
│   │   ├── companies.service.ts
│   │   ├── users.service.ts
│   │   ├── videos.service.ts
│   │   └── reports.service.ts
│   │
│   ├── integrations/          # External API clients
│   │   ├── hikvision/
│   │   │   ├── hikcentral.client.ts
│   │   │   ├── isapi.client.ts
│   │   │   ├── stream.proxy.ts
│   │   │   └── types.ts
│   │   └── storage/
│   │       ├── local.storage.ts
│   │       └── cloud.storage.ts
│   │
│   ├── middleware/            # Express middleware
│   │   ├── auth.middleware.ts
│   │   ├── validation.middleware.ts
│   │   ├── error.middleware.ts
│   │   ├── logging.middleware.ts
│   │   └── rateLimit.middleware.ts
│   │
│   ├── models/               # Prisma models & schemas
│   │   ├── database.ts       # Prisma client instance
│   │   ├── schemas/          # Zod validation schemas
│   │   │   ├── auth.schemas.ts
│   │   │   ├── events.schemas.ts
│   │   │   └── companies.schemas.ts
│   │   └── types/            # Generated Prisma types
│   │
│   ├── routes/               # Express routes
│   │   ├── index.ts          # Main router
│   │   ├── auth.routes.ts
│   │   ├── events.routes.ts
│   │   ├── companies.routes.ts
│   │   ├── users.routes.ts
│   │   └── videos.routes.ts
│   │
│   ├── utils/                # Utilities & helpers
│   │   ├── logger.ts
│   │   ├── constants.ts
│   │   ├── validators.ts
│   │   ├── formatters.ts
│   │   └── encryption.ts
│   │
│   ├── types/                # TypeScript definitions
│   │   ├── express.d.ts      # Express type extensions
│   │   ├── hikvision.types.ts
│   │   └── api.types.ts
│   │
│   ├── config/               # Configuration
│   │   ├── database.ts
│   │   ├── redis.ts
│   │   ├── hikvision.ts
│   │   └── environment.ts
│   │
│   └── app.ts                # Express app setup
│
├── prisma/                   # Database
│   ├── schema.prisma         # Database schema
│   ├── migrations/           # Migration files
│   ├── seeds/               # Database seeding
│   └── indexes.sql          # Custom indexes
│
├── tests/                    # Testing
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   ├── fixtures/            # Test data
│   └── setup.ts             # Test configuration
│
├── docs/                     # Documentation
│   ├── api/                 # API documentation
│   └── deployment/          # Deployment guides
│
├── scripts/                  # Utility scripts
│   ├── migration.js
│   ├── backup.js
│   └── monitoring.js
│
├── Dockerfile               # Container definition
├── docker-compose.yml       # Development environment
├── package.json
├── tsconfig.json
└── .env.example             # Environment template
```

### **2.2 Prisma Database Schema Implementación**

```prisma
// prisma/schema.prisma - Production Ready
generator client {
  provider = "prisma-client-js"
  output   = "../src/types/generated"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

// ============================================
// CORE ENTITIES - FASE 1
// ============================================

model Company {
  id                String   @id @default(uuid()) @db.VarChar(36)
  rut               String   @unique @db.VarChar(12) // RUT chileno formato: 12345678-9
  name              String   @db.VarChar(200)
  businessName      String?  @db.VarChar(200)
  
  // Contact Information
  address           String   @db.VarChar(300)
  city              String   @db.VarChar(100)
  region            String   @db.VarChar(100)
  phone             String   @db.VarChar(20)
  email             String   @db.VarChar(100)
  
  // Primary Contact (JSON)
  primaryContact    Json     // {name, position, phone, email}
  
  // Status
  isActive          Boolean  @default(true)
  
  // FASE 2 - Advanced Config
  advancedConfigId  String?  @unique @db.VarChar(36)
  advancedConfig    CompanyAdvancedConfig? @relation(fields: [advancedConfigId], references: [id])
  
  // Relationships
  events            Event[]
  users             User[]
  
  // Audit
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt
  createdBy         String   @db.VarChar(36)
  createdByUser     User     @relation("CompanyCreator", fields: [createdBy], references: [id])
  
  // Indexes for performance
  @@index([isActive])
  @@index([name])
  @@index([rut])
  @@map("companies")
}

model User {
  id                    String    @id @default(uuid()) @db.VarChar(36)
  email                 String    @unique @db.VarChar(100)
  password              String    @db.VarChar(255) // bcrypt hash
  
  // Personal Information
  firstName             String    @db.VarChar(50)
  lastName              String    @db.VarChar(50)
  phone                 String?   @db.VarChar(20)
  
  // Role & Permissions
  role                  UserRole
  
  // Company Association
  companyId             String?   @db.VarChar(36)
  company               Company?  @relation(fields: [companyId], references: [id])
  department            String?   @db.VarChar(100)
  position              String?   @db.VarChar(100)
  
  // Security & Status
  isActive              Boolean   @default(true)
  emailVerified         Boolean   @default(false)
  lastLogin             DateTime?
  failedLoginAttempts   Int       @default(0)
  lockedUntil           DateTime?
  
  // Preferences
  preferencesId         String?   @unique @db.VarChar(36)
  preferences           UserPreferences? @relation(fields: [preferencesId], references: [id])
  
  // FASE 2 - Advanced Profile
  advancedProfileId     String?   @unique @db.VarChar(36)
  advancedProfile       UserAdvancedProfile? @relation(fields: [advancedProfileId], references: [id])
  
  // Relationships
  permissions           UserPermission[]
  createdEvents         Event[]   @relation("EventCreator")
  createdMetadata       BasicEventMetadata[]
  createdCompanies      Company[] @relation("CompanyCreator")
  auditLogs             AuditLog[]
  
  // Audit
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt
  createdBy             String?   @db.VarChar(36)
  
  // Constraints - Unique name per company
  @@unique([firstName, lastName, companyId], name: "unique_name_per_company")
  @@index([email])
  @@index([companyId, isActive])
  @@index([role, isActive])
  @@map("users")
}

model Event {
  id                String   @id @default(uuid()) @db.VarChar(36)
  licensePlate      String   @db.VarChar(10) // Chilean format: ABC123 or ABCD12
  eventDateTime     DateTime
  confidence        Float    @db.Float // ANPR confidence 0-100
  
  // Company Association
  companyId         String   @db.VarChar(36)
  company           Company  @relation(fields: [companyId], references: [id])
  
  // ANPR Data (JSON for flexibility)
  primaryCamera     Json     // {id, image, confidence, plateReading}
  secondaryCamera   Json?    // Optional secondary camera
  
  // Status & Flags
  status            EventStatus
  hasBasicMetadata  Boolean  @default(false)
  readyForPhase2    Boolean  @default(false)
  
  // Video Files (JSON array of video file objects)
  documentaryVideos Json     // [{cameraId, filename, duration, size}]
  thumbnailPath     String?  @db.VarChar(500)
  
  // Relationships
  basicMetadata     BasicEventMetadata?
  discrepancies     ReturnDiscrepancy[] // FASE 2
  inventoryCount    DetailedInventoryCount? // FASE 2
  
  // Audit
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt
  processedAt       DateTime?
  createdBy         String   @db.VarChar(36)
  createdByUser     User     @relation("EventCreator", fields: [createdBy], references: [id])
  
  // Critical indexes for <2s searches
  @@index([licensePlate])
  @@index([companyId, eventDateTime])
  @@index([status, hasBasicMetadata])
  @@index([companyId, licensePlate, eventDateTime], name: "search_combined")
  @@map("events")
}

model BasicEventMetadata {
  id                String   @id @default(uuid()) @db.VarChar(36)
  eventId           String   @unique @db.VarChar(36)
  event             Event    @relation(fields: [eventId], references: [id], onDelete: Cascade)
  
  // Company Reference (redundant for performance)
  companyId         String   @db.VarChar(36)
  
  // Return Information (JSON for flexibility)
  basicReturnInfo   Json     // {guideNumber?, guideDate?, originProject?, cargoDescription?, observations?}
  
  // Registration Info
  registeredBy      Json     // {userId, timestamp}
  
  // Ready for FASE 2
  readyForDetailedProcessing Boolean @default(false)
  
  // Audit
  createdAt         DateTime @default(now())
  updatedAt         DateTime @updatedAt
  lastModifiedBy    String?  @db.VarChar(36)
  createdBy         String   @db.VarChar(36)
  createdByUser     User     @relation(fields: [createdBy], references: [id])
  
  // Index for guide number searches
  @@index([companyId])
  @@map("basic_event_metadata")
}

model UserPermission {
  id         String     @id @default(uuid()) @db.VarChar(36)
  userId     String     @db.VarChar(36)
  user       User       @relation(fields: [userId], references: [id], onDelete: Cascade)
  permission Permission
  grantedAt  DateTime   @default(now())
  grantedBy  String     @db.VarChar(36)
  expiresAt  DateTime?
  
  // Fast permission checks
  @@index([userId, permission])
  @@map("user_permissions")
}

model UserPreferences {
  id              String       @id @default(uuid()) @db.VarChar(36)
  userId          String       @db.VarChar(36)
  user            User?
  
  language        Language     @default(ES)
  timezone        String       @default("America/Santiago") @db.VarChar(50)
  theme           Theme        @default(LIGHT)
  
  // UI Preferences
  defaultPageSize Int          @default(25)
  videoQuality    VideoQuality @default(HIGH)
  autoPlay        Boolean      @default(false)
  
  updatedAt       DateTime     @updatedAt
  
  @@map("user_preferences")
}

model AuditLog {
  id           String       @id @default(uuid()) @db.VarChar(36)
  userId       String       @db.VarChar(36)
  user         User         @relation(fields: [userId], references: [id])
  
  action       AuditAction
  resourceType ResourceType
  resourceId   String       @db.VarChar(36)
  
  // Context
  ipAddress    String       @db.VarChar(45) // IPv6 support
  userAgent    String       @db.Text
  timestamp    DateTime     @default(now())
  
  // Action Data (JSON for flexibility)
  beforeState  Json?        // Previous state for updates
  afterState   Json?        // New state for updates
  
  // Metadata
  companyId    String?      @db.VarChar(36) // For company filtering
  sessionId    String       @db.VarChar(255)
  
  // Partitioned by month for performance
  @@index([timestamp])
  @@index([userId, timestamp])
  @@index([action, timestamp])
  @@map("audit_logs")
}

// ============================================
// FASE 2 - ADVANCED ENTITIES
// ============================================

model CompanyAdvancedConfig {
  id                    String      @id @default(uuid()) @db.VarChar(36)
  companyId             String      @unique @db.VarChar(36)
  company               Company?
  
  defaultReturnPeriod   Int         @default(30) // days
  allowedGracePeriod    Int         @default(7)  // days
  requiresApproval      Boolean     @default(false)
  autoNotifications     Boolean     @default(true)
  creditStatus          CreditStatus @default(GOOD)
  
  createdAt             DateTime    @default(now())
  updatedAt             DateTime    @updatedAt
  
  @@map("company_advanced_configs")
}

model UserAdvancedProfile {
  id                      String            @id @default(uuid()) @db.VarChar(36)
  userId                  String            @db.VarChar(36)
  user                    User?
  
  certificationLevel      CertificationLevel @default(BASIC)
  canApproveDiscrepancies Boolean           @default(false)
  maxDiscrepancyValue     Float             @default(0)
  specializedTypes        Json              // JSON array of scaffolding types
  
  // Advanced Notifications (JSON)
  advancedNotifications   Json              // {returnReminders, discrepancyAlerts, approvalRequests}
  
  createdAt               DateTime          @default(now())
  updatedAt               DateTime          @updatedAt
  
  @@map("user_advanced_profiles")
}

model ScaffoldingItemType {
  id                    String              @id @default(uuid()) @db.VarChar(36)
  code                  String              @unique @db.VarChar(50) // PAN-60x240
  description           String              @db.VarChar(200)
  category              ScaffoldingCategory
  
  // Technical Specifications (JSON)
  dimensions            Json                // {width, height, depth?}
  weight                Float               // kg
  material              MaterialType
  
  // Business Configuration
  standardRentalPeriod  Int                 // days
  replacementCost       Float               // currency
  repairThreshold       Float               // percentage
  
  isActive              Boolean             @default(true)
  
  // Relationships
  inventoryItems        ScaffoldingItemCount[]
  
  createdAt             DateTime            @default(now())
  updatedAt             DateTime            @updatedAt
  
  @@index([code])
  @@index([category, isActive])
  @@map("scaffolding_item_types")
}

model DetailedInventoryCount {
  id                  String                @id @default(uuid()) @db.VarChar(36)
  eventId             String                @unique @db.VarChar(36)
  event               Event                 @relation(fields: [eventId], references: [id])
  
  // Count Information
  countedBy           String                @db.VarChar(36)
  countedAt           DateTime
  reviewedBy          String?               @db.VarChar(36)
  reviewedAt          DateTime?
  
  status              CountStatus           @default(IN_PROGRESS)
  
  // Items
  items               ScaffoldingItemCount[]
  
  // Calculated Summary (JSON)
  summary             Json                  // {totalItemsExpected, totalItemsFound, totalDiscrepancies, valueAtRisk, riskLevel}
  
  observations        String?               @db.Text
  
  createdAt           DateTime              @default(now())
  updatedAt           DateTime              @updatedAt
  
  @@map("detailed_inventory_counts")
}

model ScaffoldingItemCount {
  id                  String                @id @default(uuid()) @db.VarChar(36)
  inventoryCountId    String                @db.VarChar(36)
  inventoryCount      DetailedInventoryCount @relation(fields: [inventoryCountId], references: [id])
  
  itemTypeId          String                @db.VarChar(36)
  itemType            ScaffoldingItemType   @relation(fields: [itemTypeId], references: [id])
  
  // Quantities
  expectedQuantity    Int
  countedQuantity     Int
  
  // Condition Breakdown (JSON)
  conditionBreakdown  Json                  // {excellent, good, fair, poor, damaged, missing}
  
  // Calculated Discrepancy (JSON)
  discrepancy         Json                  // {quantity, percentage, estimatedCost}
  
  itemObservations    String?               @db.Text
  photoEvidence       Json                  // JSON array of photo URLs
  
  @@map("scaffolding_item_counts")
}

model ReturnDiscrepancy {
  id                  String            @id @default(uuid()) @db.VarChar(36)
  eventId             String            @db.VarChar(36)
  event               Event             @relation(fields: [eventId], references: [id])
  
  type                DiscrepancyType
  itemCode            String            @db.VarChar(50)
  expectedQuantity    Int
  actualQuantity      Int
  difference          Int               // calculated: actual - expected
  percentageVariance  Float             // % variance
  
  impactLevel         ImpactLevel
  
  // Resolution
  resolution          String?           @db.Text
  resolvedBy          String?           @db.VarChar(36)
  resolvedAt          DateTime?
  
  status              DiscrepancyStatus @default(PENDING)
  requiresApproval    Boolean           @default(false)
  approvedBy          String?           @db.VarChar(36)
  approvedAt          DateTime?
  
  // Financial Impact (FASE 2)
  estimatedCost       Float?
  actualCost          Float?
  
  createdAt           DateTime          @default(now())
  updatedAt           DateTime          @updatedAt
  
  @@index([impactLevel, status])
  @@index([resolvedBy, resolvedAt])
  @@map("return_discrepancies")
}

// ============================================
// ENUMS
// ============================================

enum UserRole {
  ADMINISTRATOR
  SUPERVISOR
  OPERATOR
  CLIENT_USER
}

enum Permission {
  // Events
  READ_EVENTS
  WRITE_BASIC_METADATA
  EDIT_OWN_METADATA
  DELETE_EVENTS
  
  // Videos
  VIEW_VIDEOS
  DOWNLOAD_VIDEOS
  EXPORT_VIDEO_SEGMENTS
  
  // Search
  SEARCH_ALL_COMPANIES
  SEARCH_OWN_COMPANY
  ADVANCED_SEARCH
  
  // Administration
  MANAGE_USERS
  MANAGE_COMPANIES
  SYSTEM_CONFIG
  VIEW_AUDIT_LOGS
  
  // Reports
  GENERATE_BASIC_REPORTS
  GENERATE_DETAILED_REPORTS
  EXPORT_DATA
  SCHEDULE_REPORTS
}

enum EventStatus {
  DETECTED
  DOCUMENTED
  VALIDATED
  ARCHIVED
}

enum Language {
  ES
  EN
}

enum Theme {
  LIGHT
  DARK
  AUTO
}

enum VideoQuality {
  HIGH
  MEDIUM
  LOW
  AUTO
}

enum AuditAction {
  LOGIN
  LOGOUT
  VIEW_EVENT
  UPDATE_METADATA
  DOWNLOAD_VIDEO
  SEARCH_EVENTS
  EXPORT_DATA
  CREATE_USER
  MODIFY_PERMISSIONS
}

enum ResourceType {
  USER
  COMPANY
  EVENT
  VIDEO
  REPORT
}

// FASE 2 Enums
enum CreditStatus {
  EXCELLENT
  GOOD
  WARNING
  BLOCKED
}

enum CertificationLevel {
  BASIC
  INTERMEDIATE
  EXPERT
  MASTER
}

enum ScaffoldingCategory {
  PANELS
  CORNERS
  SUPPORTS
  ACCESSORIES
}

enum MaterialType {
  STEEL
  ALUMINUM
  COMPOSITE
}

enum CountStatus {
  IN_PROGRESS
  PENDING_REVIEW
  APPROVED
  REJECTED
  REQUIRES_RECOUNT
}

enum RiskLevel {
  MINIMAL
  LOW
  MODERATE
  HIGH
  CRITICAL
}

enum DiscrepancyType {
  QUANTITY_SHORTAGE
  QUANTITY_EXCESS
  CONDITION_DAMAGE
  MISSING_ITEM
  UNAUTHORIZED_ITEM
}

enum ImpactLevel {
  LOW
  MEDIUM
  HIGH
  CRITICAL
}

enum DiscrepancyStatus {
  PENDING
  IN_REVIEW
  RESOLVED
  ESCALATED
  CLOSED
}
```

### **2.3 Hikvision Integration Architecture**

```typescript
// src/integrations/hikvision/hikcentral.client.ts
import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { logger } from '../../utils/logger';

interface HikCentralConfig {
  baseUrl: string;
  username: string;
  password: string;
  timeout: number;
}

interface AuthResponse {
  accessToken: string;
  tokenType: string;
  refreshToken: string;
  expiresIn: number;
}

interface ANPREvent {
  plateNumber: string;
  confidence: number;
  captureTime: string;
  cameraIndexCode: string;
  picUri: string;
}

export class HikCentralClient {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private tokenExpiry: Date | null = null;
  private refreshToken: string | null = null;

  constructor(private config: HikCentralConfig) {
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    // Request interceptor for automatic token injection
    this.client.interceptors.request.use(async (config) => {
      const token = await this.getValidToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for automatic token refresh
    this.client.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401 && !error.config._retry) {
          error.config._retry = true;
          await this.authenticate();
          return this.client.request(error.config);
        }
        return Promise.reject(error);
      }
    );
  }

  /**
   * Authenticate with HikCentral and get access token
   */
  async authenticate(): Promise<string> {
    try {
      const response: AxiosResponse<AuthResponse> = await this.client.post('/oauth/token', {
        grant_type: 'password',
        username: this.config.username,
        password: this.config.password,
        scope: 'read write'
      });

      const { accessToken, expiresIn, refreshToken } = response.data;
      
      this.accessToken = accessToken;
      this.refreshToken = refreshToken;
      this.tokenExpiry = new Date(Date.now() + (expiresIn * 1000) - 60000); // 1 minute buffer

      logger.info('HikCentral authentication successful');
      return accessToken;

    } catch (error) {
      logger.error('HikCentral authentication failed:', error);
      throw new Error('Failed to authenticate with HikCentral');
    }
  }

  /**
   * Get valid token, refresh if necessary
   */
  private async getValidToken(): Promise<string | null> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.accessToken;
    }

    if (this.refreshToken) {
      try {
        await this.refreshAccessToken();
        return this.accessToken;
      } catch (error) {
        logger.warn('Token refresh failed, re-authenticating');
      }
    }

    return await this.authenticate();
  }

  /**
   * Refresh access token using refresh token
   */
  private async refreshAccessToken(): Promise<void> {
    const response: AxiosResponse<AuthResponse> = await this.client.post('/oauth/token', {
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken
    });

    const { accessToken, expiresIn, refreshToken } = response.data;
    
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiry = new Date(Date.now() + (expiresIn * 1000) - 60000);
  }

  /**
   * Subscribe to ANPR events
   */
  async subscribeToANPREvents(callback: (event: ANPREvent) => void): Promise<void> {
    try {
      const response = await this.client.post('/event/subscription', {
        eventTypes: ['anpr'],
        eventLevels: ['normal', 'major'],
        eventSources: ['camera'],
        callbackUrl: process.env.ANPR_CALLBACK_URL
      });

      logger.info('ANPR event subscription created:', response.data);
    } catch (error) {
      logger.error('Failed to subscribe to ANPR events:', error);
      throw error;
    }
  }

  /**
   * Get cameras list
   */
  async getCameras(): Promise<any[]> {
    try {
      const response = await this.client.get('/resource/camera/search', {
        params: {
          pageNo: 1,
          pageSize: 1000
        }
      });

      return response.data.list || [];
    } catch (error) {
      logger.error('Failed to get cameras:', error);
      throw error;
    }
  }

  /**
   * Get live stream URL for camera
   */
  async getLiveStreamUrl(cameraId: string, streamType: 'main' | 'sub' = 'main'): Promise<string> {
    try {
      const response = await this.client.post('/video/url', {
        cameraIndexCode: cameraId,
        streamType,
        protocol: 'rtsp',
        transmode: 1
      });

      return response.data.url;
    } catch (error) {
      logger.error('Failed to get live stream URL:', error);
      throw error;
    }
  }

  /**
   * Get playback URL for recorded video
   */
  async getPlaybackUrl(cameraId: string, startTime: string, endTime: string): Promise<string> {
    try {
      const response = await this.client.post('/video/playback/url', {
        cameraIndexCode: cameraId,
        startTime,
        endTime,
        protocol: 'rtsp'
      });

      return response.data.url;
    } catch (error) {
      logger.error('Failed to get playback URL:', error);
      throw error;
    }
  }

  /**
   * Download video segment
   */
  async downloadVideo(cameraId: string, startTime: string, endTime: string): Promise<Buffer> {
    try {
      const response = await this.client.post('/video/download', {
        cameraIndexCode: cameraId,
        startTime,
        endTime,
        downloadSpeed: 4 // 4x speed
      }, {
        responseType: 'arraybuffer'
      });

      return Buffer.from(response.data);
    } catch (error) {
      logger.error('Failed to download video:', error);
      throw error;
    }
  }

  /**
   * Search ANPR events
   */
  async searchANPREvents(params: {
    startTime: string;
    endTime: string;
    cameraIds?: string[];
    plateNumber?: string;
    pageNo?: number;
    pageSize?: number;
  }): Promise<ANPREvent[]> {
    try {
      const response = await this.client.post('/event/anpr/search', {
        startTime: params.startTime,
        endTime: params.endTime,
        cameraIndexCodes: params.cameraIds,
        plateNumber: params.plateNumber,
        pageNo: params.pageNo || 1,
        pageSize: params.pageSize || 100
      });

      return response.data.list || [];
    } catch (error) {
      logger.error('Failed to search ANPR events:', error);
      throw error;
    }
  }
}
```

### **2.4 ISAPI Direct Client**

```typescript
// src/integrations/hikvision/isapi.client.ts
import axios, { AxiosInstance } from 'axios';
import { createHash } from 'crypto';

interface ISAPIConfig {
  ip: string;
  port: number;
  username: string;
  password: string;
  timeout: number;
}

export class ISAPIClient {
  private client: AxiosInstance;
  private digestAuth: string | null = null;

  constructor(private config: ISAPIConfig) {
    this.client = axios.create({
      baseURL: `http://${config.ip}:${config.port}/ISAPI`,
      timeout: config.timeout,
      auth: {
        username: config.username,
        password: config.password
      }
    });
  }

  /**
   * Get device information
   */
  async getDeviceInfo(): Promise<any> {
    try {
      const response = await this.client.get('/System/deviceInfo');
      return response.data;
    } catch (error) {
      logger.error('Failed to get device info:', error);
      throw error;
    }
  }

  /**
   * Get camera capabilities
   */
  async getCameraCapabilities(): Promise<any> {
    try {
      const response = await this.client.get('/System/Video/inputs/channels/1/capabilities');
      return response.data;
    } catch (error) {
      logger.error('Failed to get camera capabilities:', error);
      throw error;
    }
  }

  /**
   * Capture still image
   */
  async captureImage(channelId: number = 1): Promise<Buffer> {
    try {
      const response = await this.client.get(`/Streaming/channels/${channelId}01/picture`, {
        responseType: 'arraybuffer'
      });

      return Buffer.from(response.data);
    } catch (error) {
      logger.error('Failed to capture image:', error);
      throw error;
    }
  }

  /**
   * Start PTZ control
   */
  async startPTZ(channelId: number, command: string, speed: number): Promise<void> {
    try {
      await this.client.put(`/PTZCtrl/channels/${channelId}/continuous`, {
        PTZData: {
          pan: command.includes('LEFT') ? -speed : command.includes('RIGHT') ? speed : 0,
          tilt: command.includes('UP') ? speed : command.includes('DOWN') ? -speed : 0,
          zoom: command.includes('ZOOM_IN') ? speed : command.includes('ZOOM_OUT') ? -speed : 0
        }
      });
    } catch (error) {
      logger.error('Failed to start PTZ:', error);
      throw error;
    }
  }

  /**
   * Stop PTZ control
   */
  async stopPTZ(channelId: number): Promise<void> {
    try {
      await this.client.put(`/PTZCtrl/channels/${channelId}/continuous`, {
        PTZData: {
          pan: 0,
          tilt: 0,
          zoom: 0
        }
      });
    } catch (error) {
      logger.error('Failed to stop PTZ:', error);
      throw error;
    }
  }
}
```

### **2.5 Video Stream Proxy**

```typescript
// src/integrations/hikvision/stream.proxy.ts
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import ffmpeg from 'fluent-ffmpeg';
import { logger } from '../../utils/logger';

export class VideoStreamProxy {
  private app: express.Application;

  constructor() {
    this.app = express();
    this.setupRoutes();
  }

  private setupRoutes(): void {
    // RTSP to HTTP proxy for live streams
    this.app.use('/live/:cameraId', this.createLiveStreamProxy());
    
    // HLS stream endpoint
    this.app.use('/hls/:cameraId', this.createHLSStreamProxy());
    
    // Video download endpoint
    this.app.get('/download/:cameraId', this.handleVideoDownload.bind(this));
    
    // Thumbnail generation
    this.app.get('/thumbnail/:cameraId', this.handleThumbnailGeneration.bind(this));
  }

  private createLiveStreamProxy() {
    return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
      const { cameraId } = req.params;
      
      try {
        // Get RTSP URL from HikCentral
        const hikCentral = new HikCentralClient(/* config */);
        const rtspUrl = await hikCentral.getLiveStreamUrl(cameraId);
        
        // Set up FFmpeg stream conversion
        const ffmpegCommand = ffmpeg(rtspUrl)
          .inputOptions([
            '-rtsp_transport', 'tcp',
            '-allowed_media_types', 'video'
          ])
          .outputOptions([
            '-f', 'mjpeg',
            '-q:v', '3',
            '-r', '25'
          ])
          .on('start', () => {
            logger.info(`Started live stream for camera ${cameraId}`);
          })
          .on('error', (err) => {
            logger.error(`Live stream error for camera ${cameraId}:`, err);
            res.status(500).send('Stream error');
          });

        res.setHeader('Content-Type', 'multipart/x-mixed-replace; boundary=ffmpeg');
        ffmpegCommand.pipe(res);

      } catch (error) {
        logger.error('Failed to create live stream proxy:', error);
        res.status(500).send('Failed to start stream');
      }
    };
  }

  private createHLSStreamProxy() {
    return async (req: express.Request, res: express.Response) => {
      const { cameraId } = req.params;
      const { segment } = req.query;

      try {
        if (segment) {
          // Serve HLS segment
          const segmentPath = `/tmp/hls/${cameraId}/${segment}`;
          res.sendFile(segmentPath);
        } else {
          // Serve HLS playlist
          const playlistPath = `/tmp/hls/${cameraId}/playlist.m3u8`;
          res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
          res.sendFile(playlistPath);
        }
      } catch (error) {
        logger.error('HLS proxy error:', error);
        res.status(500).send('HLS error');
      }
    };
  }

  private async handleVideoDownload(req: express.Request, res: express.Response): Promise<void> {
    const { cameraId } = req.params;
    const { startTime, endTime, quality = 'high' } = req.query as any;

    try {
      const hikCentral = new HikCentralClient(/* config */);
      const playbackUrl = await hikCentral.getPlaybackUrl(cameraId, startTime, endTime);

      const qualityMap = {
        high: { bitrate: '4000k', resolution: '1920x1080' },
        medium: { bitrate: '2000k', resolution: '1280x720' },
        low: { bitrate: '800k', resolution: '854x480' }
      };

      const settings = qualityMap[quality as keyof typeof qualityMap] || qualityMap.high;

      res.setHeader('Content-Type', 'video/mp4');
      res.setHeader('Content-Disposition', `attachment; filename="video_${cameraId}_${Date.now()}.mp4"`);

      ffmpeg(playbackUrl)
        .outputOptions([
          '-f', 'mp4',
          '-movflags', 'frag_keyframe+empty_moov',
          '-b:v', settings.bitrate,
          '-s', settings.resolution,
          '-c:v', 'libx264',
          '-preset', 'fast'
        ])
        .on('start', () => {
          logger.info(`Started video download for camera ${cameraId}`);
        })
        .on('progress', (progress) => {
          logger.debug(`Download progress: ${progress.percent}%`);
        })
        .on('error', (err) => {
          logger.error('Video download error:', err);
          res.status(500).end();
        })
        .pipe(res);

    } catch (error) {
      logger.error('Failed to handle video download:', error);
      res.status(500).send('Download failed');
    }
  }

  private async handleThumbnailGeneration(req: express.Request, res: express.Response): Promise<void> {
    const { cameraId } = req.params;
    const { timestamp } = req.query as any;

    try {
      const hikCentral = new HikCentralClient(/* config */);
      const playbackUrl = await hikCentral.getPlaybackUrl(cameraId, timestamp, timestamp);

      res.setHeader('Content-Type', 'image/jpeg');

      ffmpeg(playbackUrl)
        .seekInput(0)
        .frames(1)
        .outputOptions([
          '-f', 'image2',
          '-q:v', '2'
        ])
        .on('error', (err) => {
          logger.error('Thumbnail generation error:', err);
          res.status(500).end();
        })
        .pipe(res);

    } catch (error) {
      logger.error('Failed to generate thumbnail:', error);
      res.status(500).send('Thumbnail generation failed');
    }
  }

  public getApp(): express.Application {
    return this.app;
  }
}
```

### **2.6 Business Logic Services**

```typescript
// src/services/events.service.ts
import { PrismaClient, Event, EventStatus, Company } from '../types/generated';
import { HikCentralClient } from '../integrations/hikvision/hikcentral.client';
import { logger } from '../utils/logger';

interface SearchEventsParams {
  licensePlate?: string;
  companyId?: string;
  startDate?: Date;
  endDate?: Date;
  status?: EventStatus;
  hasMetadata?: boolean;
  page?: number;
  limit?: number;
}

interface CreateEventParams {
  licensePlate: string;
  eventDateTime: Date;
  confidence: number;
  companyId: string;
  primaryCamera: {
    id: string;
    image: string;
    confidence: number;
    plateReading: string;
  };
  secondaryCamera?: {
    id: string;
    image: string;
    confidence: number;
    plateReading: string;
  };
  documentaryVideos: Array<{
    cameraId: string;
    filename: string;
    duration: number;
    size: number;
  }>;
  createdBy: string;
}

export class EventsService {
  constructor(
    private prisma: PrismaClient,
    private hikCentral: HikCentralClient
  ) {}

  /**
   * Search events with optimized performance (<2 seconds)
   */
  async searchEvents(params: SearchEventsParams, userCompanyId?: string): Promise<{
    events: Event[];
    total: number;
    page: number;
    totalPages: number;
  }> {
    const {
      licensePlate,
      companyId,
      startDate,
      endDate,
      status,
      hasMetadata,
      page = 1,
      limit = 25
    } = params;

    const skip = (page - 1) * limit;

    // Build where clause optimized for indexes
    const where: any = {};

    // Client users can only see their company's events
    if (userCompanyId) {
      where.companyId = userCompanyId;
    } else if (companyId) {
      where.companyId = companyId;
    }

    if (licensePlate) {
      where.licensePlate = {
        contains: licensePlate.toUpperCase()
      };
    }

    if (startDate || endDate) {
      where.eventDateTime = {};
      if (startDate) where.eventDateTime.gte = startDate;
      if (endDate) where.eventDateTime.lte = endDate;
    }

    if (status) {
      where.status = status;
    }

    if (hasMetadata !== undefined) {
      where.hasBasicMetadata = hasMetadata;
    }

    try {
      // Execute both queries in parallel for performance
      const [events, total] = await Promise.all([
        this.prisma.event.findMany({
          where,
          include: {
            company: {
              select: {
                id: true,
                name: true,
                rut: true
              }
            },
            basicMetadata: {
              select: {
                id: true,
                basicReturnInfo: true,
                readyForDetailedProcessing: true
              }
            }
          },
          orderBy: {
            eventDateTime: 'desc'
          },
          skip,
          take: limit
        }),
        this.prisma.event.count({ where })
      ]);

      const totalPages = Math.ceil(total / limit);

      logger.info(`Search executed: ${events.length} events found in ${total} total`);

      return {
        events,
        total,
        page,
        totalPages
      };

    } catch (error) {
      logger.error('Error searching events:', error);
      throw new Error('Failed to search events');
    }
  }

  /**
   * Create new event from ANPR detection
   */
  async createEvent(params: CreateEventParams): Promise<Event> {
    try {
      // Validate company exists
      const company = await this.prisma.company.findUnique({
        where: { id: params.companyId }
      });

      if (!company) {
        throw new Error('Company not found');
      }

      // Create event with optimized data structure
      const event = await this.prisma.event.create({
        data: {
          licensePlate: params.licensePlate.toUpperCase(),
          eventDateTime: params.eventDateTime,
          confidence: params.confidence,
          companyId: params.companyId,
          primaryCamera: params.primaryCamera,
          secondaryCamera: params.secondaryCamera || null,
          status: EventStatus.DETECTED,
          hasBasicMetadata: false,
          readyForPhase2: false,
          documentaryVideos: params.documentaryVideos,
          createdBy: params.createdBy
        },
        include: {
          company: true
        }
      });

      logger.info(`Event created: ${event.id} for plate ${event.licensePlate}`);

      // Trigger async thumbnail generation
      this.generateThumbnailAsync(event.id, params.primaryCamera.id, params.eventDateTime);

      return event;

    } catch (error) {
      logger.error('Error creating event:', error);
      throw new Error('Failed to create event');
    }
  }

  /**
   * Get event by ID with security check
   */
  async getEventById(eventId: string, userCompanyId?: string): Promise<Event | null> {
    try {
      const where: any = { id: eventId };
      
      // Client users can only access their company's events
      if (userCompanyId) {
        where.companyId = userCompanyId;
      }

      const event = await this.prisma.event.findUnique({
        where,
        include: {
          company: true,
          basicMetadata: true
        }
      });

      return event;

    } catch (error) {
      logger.error('Error getting event by ID:', error);
      throw new Error('Failed to get event');
    }
  }

  /**
   * Update event status
   */
  async updateEventStatus(eventId: string, status: EventStatus, userId: string): Promise<Event> {
    try {
      const event = await this.prisma.event.update({
        where: { id: eventId },
        data: {
          status,
          processedAt: status === EventStatus.VALIDATED ? new Date() : undefined
        }
      });

      // Log the status change for audit
      await this.logEventAction(eventId, 'STATUS_UPDATE', userId, { newStatus: status });

      return event;

    } catch (error) {
      logger.error('Error updating event status:', error);
      throw new Error('Failed to update event status');
    }
  }

  /**
   * Sync events from Hikvision
   */
  async syncFromHikvision(startTime: Date, endTime: Date): Promise<number> {
    try {
      const anprEvents = await this.hikCentral.searchANPREvents({
        startTime: startTime.toISOString(),
        endTime: endTime.toISOString(),
        pageSize: 1000
      });

      let syncedCount = 0;

      for (const anprEvent of anprEvents) {
        // Check if event already exists
        const existingEvent = await this.prisma.event.findFirst({
          where: {
            licensePlate: anprEvent.plateNumber,
            eventDateTime: new Date(anprEvent.captureTime)
          }
        });

        if (existingEvent) {
          continue; // Skip if already exists
        }

        // Try to match company by license plate (business logic)
        const companyId = await this.matchCompanyByLicensePlate(anprEvent.plateNumber);
        
        if (!companyId) {
          logger.warn(`No company found for plate: ${anprEvent.plateNumber}`);
          continue;
        }

        // Create event from ANPR data
        await this.createEvent({
          licensePlate: anprEvent.plateNumber,
          eventDateTime: new Date(anprEvent.captureTime),
          confidence: anprEvent.confidence,
          companyId,
          primaryCamera: {
            id: anprEvent.cameraIndexCode,
            image: anprEvent.picUri,
            confidence: anprEvent.confidence,
            plateReading: anprEvent.plateNumber
          },
          documentaryVideos: [], // Will be populated separately
          createdBy: 'system' // System user ID
        });

        syncedCount++;
      }

      logger.info(`Synced ${syncedCount} events from Hikvision`);
      return syncedCount;

    } catch (error) {
      logger.error('Error syncing from Hikvision:', error);
      throw new Error('Failed to sync events');
    }
  }

  /**
   * Generate thumbnail asynchronously
   */
  private async generateThumbnailAsync(eventId: string, cameraId: string, timestamp: Date): Promise<void> {
    try {
      // This would typically be handled by a background job queue
      setTimeout(async () => {
        const thumbnailPath = `/thumbnails/${eventId}_${cameraId}_${timestamp.getTime()}.jpg`;
        
        // Update event with thumbnail path
        await this.prisma.event.update({
          where: { id: eventId },
          data: { thumbnailPath }
        });

        logger.info(`Thumbnail generated for event ${eventId}`);
      }, 5000); // 5 second delay to allow video processing

    } catch (error) {
      logger.error('Error generating thumbnail:', error);
    }
  }

  /**
   * Match company by license plate (business logic placeholder)
   */
  private async matchCompanyByLicensePlate(licensePlate: string): Promise<string | null> {
    // This is where you would implement business logic to match
    // license plates to companies based on your business rules
    // For now, return null and require manual assignment
    return null;
  }

  /**
   * Log event actions for audit trail
   */
  private async logEventAction(eventId: string, action: string, userId: string, metadata?: any): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          userId,
          action: action as any,
          resourceType: 'EVENT',
          resourceId: eventId,
          ipAddress: '127.0.0.1', // This should come from request
          userAgent: 'System',
          sessionId: 'system',
          afterState: metadata,
          timestamp: new Date()
        }
      });
    } catch (error) {
      logger.error('Error logging event action:', error);
      // Don't throw - audit logging shouldn't break main functionality
    }
  }
}
```

---

## 🎨 **3. FRONTEND ARCHITECTURE DETALLADA**

### **3.1 Estructura de Directorios Frontend**

```
frontend/
├── src/
│   ├── components/           # Reusable components
│   │   ├── common/          # Generic components
│   │   │   ├── Layout/
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── Sidebar.tsx
│   │   │   │   ├── Footer.tsx
│   │   │   │   └── Layout.tsx
│   │   │   ├── Forms/
│   │   │   │   ├── FormField.tsx
│   │   │   │   ├── FormSelect.tsx
│   │   │   │   ├── FormDatePicker.tsx
│   │   │   │   └── FormValidation.tsx
│   │   │   ├── UI/
│   │   │   │   ├── LoadingSpinner.tsx
│   │   │   │   ├── ErrorBoundary.tsx
│   │   │   │   ├── ConfirmDialog.tsx
│   │   │   │   └── NotificationSnackbar.tsx
│   │   │   └── DataDisplay/
│   │   │       ├── DataTable.tsx
│   │   │       ├── Pagination.tsx
│   │   │       ├── SearchBar.tsx
│   │   │       └── FilterPanel.tsx
│   │   │
│   │   ├── video/           # Video-specific components
│   │   │   ├── VideoPlayer/
│   │   │   │   ├── VideoPlayer.tsx
│   │   │   │   ├── VideoControls.tsx
│   │   │   │   ├── ZoomControls.tsx
│   │   │   │   ├── Timeline.tsx
│   │   │   │   └── VideoGrid.tsx
│   │   │   ├── VideoThumbnail.tsx
│   │   │   ├── CameraSelector.tsx
│   │   │   └── VideoDownload.tsx
│   │   │
│   │   ├── events/          # Event-specific components
│   │   │   ├── EventList.tsx
│   │   │   ├── EventCard.tsx
│   │   │   ├── EventDetails.tsx
│   │   │   ├── EventSearch.tsx
│   │   │   └── EventFilters.tsx
│   │   │
│   │   ├── metadata/        # Metadata forms
│   │   │   ├── BasicMetadataForm.tsx
│   │   │   ├── CompanySelector.tsx
│   │   │   ├── ReturnInfoForm.tsx
│   │   │   └── ObservationsForm.tsx
│   │   │
│   │   └── dashboard/       # Dashboard components
│   │       ├── DashboardSummary.tsx
│   │       ├── RecentEvents.tsx
│   │       ├── MetricsCards.tsx
│   │       └── QuickActions.tsx
│   │
│   ├── pages/               # Page components
│   │   ├── Auth/
│   │   │   ├── Login.tsx
│   │   │   ├── Register.tsx
│   │   │   └── ForgotPassword.tsx
│   │   ├── Dashboard/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── OperatorDashboard.tsx
│   │   │   ├── ClientDashboard.tsx
│   │   │   └── AdminDashboard.tsx
│   │   ├── Events/
│   │   │   ├── EventsList.tsx
│   │   │   ├── EventDetails.tsx
│   │   │   ├── EventVideo.tsx
│   │   │   └── EventMetadata.tsx
│   │   ├── Companies/
│   │   │   ├── CompaniesList.tsx
│   │   │   ├── CompanyDetails.tsx
│   │   │   └── CompanyForm.tsx
│   │   ├── Users/
│   │   │   ├── UsersList.tsx
│   │   │   ├── UserDetails.tsx
│   │   │   └── UserForm.tsx
│   │   ├── Reports/
│   │   │   ├── ReportsList.tsx
│   │   │   ├── ReportBuilder.tsx
│   │   │   └── ReportViewer.tsx
│   │   └── Settings/
│   │       ├── UserSettings.tsx
│   │       ├── SystemSettings.tsx
│   │       └── Integration.tsx
│   │
│   ├── hooks/               # Custom React hooks
│   │   ├── useAuth.ts
│   │   ├── useEvents.ts
│   │   ├── useCompanies.ts
│   │   ├── useVideo.ts
│   │   ├── useSearch.ts
│   │   ├── usePermissions.ts
│   │   ├── useLocalStorage.ts
│   │   └── useDebounce.ts
│   │
│   ├── services/            # API communication
│   │   ├── api.ts           # Axios instance
│   │   ├── auth.service.ts
│   │   ├── events.service.ts
│   │   ├── companies.service.ts
│   │   ├── users.service.ts
│   │   ├── videos.service.ts
│   │   └── reports.service.ts
│   │
│   ├── store/               # Zustand stores
│   │   ├── auth.store.ts
│   │   ├── events.store.ts
│   │   ├── ui.store.ts
│   │   ├── video.store.ts
│   │   └── notifications.store.ts
│   │
│   ├── types/               # TypeScript definitions
│   │   ├── api.types.ts
│   │   ├── auth.types.ts
│   │   ├── events.types.ts
│   │   ├── video.types.ts
│   │   └── ui.types.ts
│   │
│   ├── utils/               # Utility functions
│   │   ├── constants.ts
│   │   ├── formatters.ts
│   │   ├── validators.ts
│   │   ├── permissions.ts
│   │   ├── api-helpers.ts
│   │   └── date-helpers.ts
│   │
│   ├── styles/              # Styling
│   │   ├── theme.ts         # MUI theme
│   │   ├── globals.css
│   │   └── components.css
│   │
│   └── assets/              # Static assets
│       ├── images/
│       ├── icons/
│       └── videos/
│
├── public/                  # Public assets
├── package.json
├── vite.config.ts
├── tsconfig.json
└── .env.example
```

### **3.2 Material Design v5 Theme Implementation**

```typescript
// src/styles/theme.ts
import { createTheme, ThemeOptions } from '@mui/material/styles';
import { esES } from '@mui/material/locale';

const baseThemeOptions: ThemeOptions = {
  palette: {
    primary: {
      main: '#1976d2',      // DOM brand blue
      light: '#42a5f5',
      dark: '#1565c0',
      contrastText: '#ffffff'
    },
    secondary: {
      main: '#9c27b0',      // Purple accent
      light: '#ba68c8',
      dark: '#7b1fa2',
      contrastText: '#ffffff'
    },
    error: {
      main: '#d32f2f',
      light: '#ef5350',
      dark: '#c62828'
    },
    warning: {
      main: '#ed6c02',
      light: '#ff9800',
      dark: '#e65100'
    },
    info: {
      main: '#0288d1',
      light: '#03a9f4',
      dark: '#01579b'
    },
    success: {
      main: '#2e7d32',
      light: '#4caf50',
      dark: '#1b5e20'
    },
    background: {
      default: '#fafafa',
      paper: '#ffffff'
    },
    text: {
      primary: 'rgba(0, 0, 0, 0.87)',
      secondary: 'rgba(0, 0, 0, 0.6)'
    }
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.125rem',
      fontWeight: 300,
      lineHeight: 1.167
    },
    h2: {
      fontSize: '1.5rem',
      fontWeight: 400,
      lineHeight: 1.2
    },
    h3: {
      fontSize: '1.25rem',
      fontWeight: 500,
      lineHeight: 1.167
    },
    h4: {
      fontSize: '1.125rem',
      fontWeight: 400,
      lineHeight: 1.235
    },
    h5: {
      fontSize: '1rem',
      fontWeight: 400,
      lineHeight: 1.334
    },
    h6: {
      fontSize: '0.875rem',
      fontWeight: 500,
      lineHeight: 1.6
    },
    body1: {
      fontSize: '1rem',
      lineHeight: 1.5
    },
    body2: {
      fontSize: '0.875rem',
      lineHeight: 1.43
    },
    button: {
      fontSize: '0.875rem',
      fontWeight: 500,
      lineHeight: 1.75,
      textTransform: 'uppercase' as const
    }
  },
  shape: {
    borderRadius: 8
  },
  spacing: 8,
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          textTransform: 'none',
          fontWeight: 500,
          padding: '8px 24px'
        },
        contained: {
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          '&:hover': {
            boxShadow: '0 4px 8px rgba(0,0,0,0.15)'
          }
        }
      }
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 12,
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
          '&:hover': {
            boxShadow: '0 4px 16px rgba(0,0,0,0.15)'
          }
        }
      }
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            borderRadius: 8
          }
        }
      }
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 16
        }
      }
    },
    MuiDataGrid: {
      styleOverrides: {
        root: {
          border: 'none',
          '& .MuiDataGrid-cell': {
            borderBottom: '1px solid rgba(224, 224, 224, 1)'
          },
          '& .MuiDataGrid-columnHeaders': {
            backgroundColor: '#f5f5f5',
            borderBottom: '2px solid rgba(224, 224, 224, 1)'
          }
        }
      }
    }
  }
};

// Light theme
export const lightTheme = createTheme(baseThemeOptions, esES);

// Dark theme
export const darkTheme = createTheme({
  ...baseThemeOptions,
  palette: {
    ...baseThemeOptions.palette,
    mode: 'dark',
    primary: {
      main: '#90caf9',
      light: '#e3f2fd',
      dark: '#42a5f5'
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e'
    },
    text: {
      primary: '#ffffff',
      secondary: 'rgba(255, 255, 255, 0.7)'
    }
  }
}, esES);
```

### **3.3 Video Player Component con Zoom 10x**

```typescript
// src/components/video/VideoPlayer/VideoPlayer.tsx
import React, { useRef, useEffect, useState, useCallback } from 'react';
import {
  Box,
  IconButton,
  Slider,
  Typography,
  Paper,
  Grid,
  Tooltip,
  Fab
} from '@mui/material';
import {
  PlayArrow,
  Pause,
  VolumeUp,
  VolumeOff,
  Fullscreen,
  ZoomIn,
  ZoomOut,
  PhotoCamera,
  Download,
  Settings
} from '@mui/icons-material';
import { useVideoPlayer } from '../../../hooks/useVideo';

interface VideoPlayerProps {
  eventId: string;
  cameraId: string;
  src: string;
  poster?: string;
  onTimeUpdate?: (currentTime: number) => void;
  onCapture?: (imageData: string) => void;
  className?: string;
}

export const VideoPlayer: React.FC<VideoPlayerProps> = ({
  eventId,
  cameraId,
  src,
  poster,
  onTimeUpdate,
  onCapture,
  className
}) => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const {
    isPlaying,
    currentTime,
    duration,
    volume,
    isMuted,
    isFullscreen,
    zoom,
    pan,
    play,
    pause,
    setTime,
    setVolume,
    toggleMute,
    toggleFullscreen,
    setZoom,
    setPan,
    captureFrame
  } = useVideoPlayer(videoRef);

  const [showControls, setShowControls] = useState(true);
  const [controlsTimeout, setControlsTimeout] = useState<NodeJS.Timeout | null>(null);

  // Auto-hide controls after 3 seconds of inactivity
  const resetControlsTimeout = useCallback(() => {
    if (controlsTimeout) {
      clearTimeout(controlsTimeout);
    }
    setShowControls(true);
    
    const timeout = setTimeout(() => {
      setShowControls(false);
    }, 3000);
    
    setControlsTimeout(timeout);
  }, [controlsTimeout]);

  // Handle time updates
  useEffect(() => {
    if (onTimeUpdate) {
      onTimeUpdate(currentTime);
    }
  }, [currentTime, onTimeUpdate]);

  // Handle mouse movement for controls
  const handleMouseMove = useCallback(() => {
    resetControlsTimeout();
  }, [resetControlsTimeout]);

  // Handle zoom with mouse wheel
  const handleWheel = useCallback((event: WheelEvent) => {
    event.preventDefault();
    const zoomDelta = event.deltaY > 0 ? -0.1 : 0.1;
    const newZoom = Math.max(1, Math.min(10, zoom + zoomDelta));
    setZoom(newZoom);
  }, [zoom, setZoom]);

  // Handle pan with mouse drag
  const handleMouseDown = useCallback((event: React.MouseEvent) => {
    if (zoom <= 1) return;

    const startX = event.clientX;
    const startY = event.clientY;
    const startPan = { ...pan };

    const handleMouseMove = (moveEvent: MouseEvent) => {
      const deltaX = moveEvent.clientX - startX;
      const deltaY = moveEvent.clientY - startY;
      
      setPan({
        x: startPan.x + deltaX / zoom,
        y: startPan.y + deltaY / zoom
      });
    };

    const handleMouseUp = () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  }, [zoom, pan, setPan]);

  // Set up event listeners
  useEffect(() => {
    const container = containerRef.current;
    if (container) {
      container.addEventListener('wheel', handleWheel, { passive: false });
      
      return () => {
        container.removeEventListener('wheel', handleWheel);
      };
    }
  }, [handleWheel]);

  // Handle capture
  const handleCapture = useCallback(() => {
    const imageData = captureFrame();
    if (imageData && onCapture) {
      onCapture(imageData);
    }
  }, [captureFrame, onCapture]);

  // Format time display
  const formatTime = (time: number): string => {
    const minutes = Math.floor(time / 60);
    const seconds = Math.floor(time % 60);
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
  };

  return (
    <Box
      ref={containerRef}
      className={className}
      sx={{
        position: 'relative',
        width: '100%',
        height: '100%',
        backgroundColor: '#000',
        borderRadius: 2,
        overflow: 'hidden',
        cursor: zoom > 1 ? 'grab' : 'default',
        '&:hover': {
          '& .video-controls': {
            opacity: 1
          }
        }
      }}
      onMouseMove={handleMouseMove}
    >
      {/* Video Element */}
      <video
        ref={videoRef}
        src={src}
        poster={poster}
        style={{
          width: '100%',
          height: '100%',
          objectFit: 'contain',
          transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)`,
          transformOrigin: 'center',
          transition: 'transform 0.1s ease-out'
        }}
        onMouseDown={handleMouseDown}
        onLoadedMetadata={() => {
          console.log('Video loaded:', { duration, src });
        }}
      />

      {/* Hidden canvas for frame capture */}
      <canvas
        ref={canvasRef}
        style={{ display: 'none' }}
        width={1920}
        height={1080}
      />

      {/* Video Controls Overlay */}
      <Box
        className="video-controls"
        sx={{
          position: 'absolute',
          bottom: 0,
          left: 0,
          right: 0,
          background: 'linear-gradient(transparent, rgba(0,0,0,0.7))',
          opacity: showControls ? 1 : 0,
          transition: 'opacity 0.3s ease',
          p: 2
        }}
      >
        {/* Progress Bar */}
        <Box sx={{ mb: 1 }}>
          <Slider
            value={currentTime}
            max={duration}
            onChange={(_, value) => setTime(value as number)}
            sx={{
              color: 'primary.main',
              '& .MuiSlider-thumb': {
                width: 16,
                height: 16
              },
              '& .MuiSlider-track': {
                height: 4
              },
              '& .MuiSlider-rail': {
                height: 4,
                backgroundColor: 'rgba(255,255,255,0.3)'
              }
            }}
          />
        </Box>

        {/* Control Buttons */}
        <Grid container alignItems="center" spacing={1}>
          {/* Play/Pause */}
          <Grid item>
            <IconButton
              onClick={isPlaying ? pause : play}
              sx={{ color: 'white' }}
            >
              {isPlaying ? <Pause /> : <PlayArrow />}
            </IconButton>
          </Grid>

          {/* Time Display */}
          <Grid item>
            <Typography variant="body2" sx={{ color: 'white', minWidth: '80px' }}>
              {formatTime(currentTime)} / {formatTime(duration)}
            </Typography>
          </Grid>

          {/* Volume Control */}
          <Grid item>
            <IconButton
              onClick={toggleMute}
              sx={{ color: 'white' }}
            >
              {isMuted ? <VolumeOff /> : <VolumeUp />}
            </IconButton>
          </Grid>

          <Grid item sx={{ width: 100 }}>
            <Slider
              value={isMuted ? 0 : volume}
              onChange={(_, value) => setVolume(value as number)}
              max={1}
              step={0.1}
              sx={{
                color: 'white',
                '& .MuiSlider-thumb': {
                  width: 12,
                  height: 12
                }
              }}
            />
          </Grid>

          {/* Spacer */}
          <Grid item sx={{ flexGrow: 1 }} />

          {/* Zoom Level */}
          <Grid item>
            <Typography variant="body2" sx={{ color: 'white' }}>
              {Math.round(zoom * 100)}%
            </Typography>
          </Grid>

          {/* Capture Button */}
          <Grid item>
            <Tooltip title="Capturar frame">
              <IconButton
                onClick={handleCapture}
                sx={{ color: 'white' }}
              >
                <PhotoCamera />
              </IconButton>
            </Tooltip>
          </Grid>

          {/* Fullscreen */}
          <Grid item>
            <IconButton
              onClick={toggleFullscreen}
              sx={{ color: 'white' }}
            >
              <Fullscreen />
            </IconButton>
          </Grid>
        </Grid>
      </Box>

      {/* Zoom Controls */}
      <Box
        sx={{
          position: 'absolute',
          top: 16,
          right: 16,
          display: 'flex',
          flexDirection: 'column',
          gap: 1
        }}
      >
        <Tooltip title="Zoom In">
          <Fab
            size="small"
            onClick={() => setZoom(Math.min(10, zoom + 0.5))}
            disabled={zoom >= 10}
            sx={{
              backgroundColor: 'rgba(0,0,0,0.7)',
              color: 'white',
              '&:hover': {
                backgroundColor: 'rgba(0,0,0,0.8)'
              }
            }}
          >
            <ZoomIn />
          </Fab>
        </Tooltip>

        <Tooltip title="Zoom Out">
          <Fab
            size="small"
            onClick={() => setZoom(Math.max(1, zoom - 0.5))}
            disabled={zoom <= 1}
            sx={{
              backgroundColor: 'rgba(0,0,0,0.7)',
              color: 'white',
              '&:hover': {
                backgroundColor: 'rgba(0,0,0,0.8)'
              }
            }}
          >
            <ZoomOut />
          </Fab>
        </Tooltip>

        <Tooltip title="Reset Zoom">
          <Fab
            size="small"
            onClick={() => {
              setZoom(1);
              setPan({ x: 0, y: 0 });
            }}
            disabled={zoom === 1}
            sx={{
              backgroundColor: 'rgba(0,0,0,0.7)',
              color: 'white',
              '&:hover': {
                backgroundColor: 'rgba(0,0,0,0.8)'
              }
            }}
          >
            <Settings />
          </Fab>
        </Tooltip>
      </Box>
    </Box>
  );
};
```

### **3.4 Custom Hook para Video Player**

```typescript
// src/hooks/useVideo.ts
import { useState, useEffect, useRef, useCallback } from 'react';

interface VideoState {
  isPlaying: boolean;
  currentTime: number;
  duration: number;
  volume: number;
  isMuted: boolean;
  isFullscreen: boolean;
  zoom: number;
  pan: { x: number; y: number };
}

export const useVideoPlayer = (videoRef: React.RefObject<HTMLVideoElement>) => {
  const [state, setState] = useState<VideoState>({
    isPlaying: false,
    currentTime: 0,
    duration: 0,
    volume: 1,
    isMuted: false,
    isFullscreen: false,
    zoom: 1,
    pan: { x: 0, y: 0 }
  });

  // Play video
  const play = useCallback(async () => {
    if (videoRef.current) {
      try {
        await videoRef.current.play();
        setState(prev => ({ ...prev, isPlaying: true }));
      } catch (error) {
        console.error('Error playing video:', error);
      }
    }
  }, [videoRef]);

  // Pause video
  const pause = useCallback(() => {
    if (videoRef.current) {
      videoRef.current.pause();
      setState(prev => ({ ...prev, isPlaying: false }));
    }
  }, [videoRef]);

  // Set current time
  const setTime = useCallback((time: number) => {
    if (videoRef.current) {
      videoRef.current.currentTime = time;
      setState(prev => ({ ...prev, currentTime: time }));
    }
  }, [videoRef]);

  // Set volume
  const setVolume = useCallback((volume: number) => {
    if (videoRef.current) {
      videoRef.current.volume = volume;
      setState(prev => ({ ...prev, volume, isMuted: volume === 0 }));
    }
  }, [videoRef]);

  // Toggle mute
  const toggleMute = useCallback(() => {
    if (videoRef.current) {
      const newMuted = !state.isMuted;
      videoRef.current.muted = newMuted;
      setState(prev => ({ ...prev, isMuted: newMuted }));
    }
  }, [videoRef, state.isMuted]);

  // Toggle fullscreen
  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      videoRef.current?.requestFullscreen();
      setState(prev => ({ ...prev, isFullscreen: true }));
    } else {
      document.exitFullscreen();
      setState(prev => ({ ...prev, isFullscreen: false }));
    }
  }, [videoRef]);

  // Set zoom level
  const setZoom = useCallback((zoom: number) => {
    setState(prev => ({ ...prev, zoom }));
  }, []);

  // Set pan position
  const setPan = useCallback((pan: { x: number; y: number }) => {
    setState(prev => ({ ...prev, pan }));
  }, []);

  // Capture current frame
  const captureFrame = useCallback((): string | null => {
    if (videoRef.current) {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      if (ctx) {
        canvas.width = videoRef.current.videoWidth;
        canvas.height = videoRef.current.videoHeight;
        
        ctx.drawImage(videoRef.current, 0, 0);
        return canvas.toDataURL('image/jpeg', 0.9);
      }
    }
    return null;
  }, [videoRef]);

  // Video event listeners
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    const handleTimeUpdate = () => {
      setState(prev => ({ ...prev, currentTime: video.currentTime }));
    };

    const handleDurationChange = () => {
      setState(prev => ({ ...prev, duration: video.duration }));
    };

    const handlePlay = () => {
      setState(prev => ({ ...prev, isPlaying: true }));
    };

    const handlePause = () => {
      setState(prev => ({ ...prev, isPlaying: false }));
    };

    const handleVolumeChange = () => {
      setState(prev => ({
        ...prev,
        volume: video.volume,
        isMuted: video.muted
      }));
    };

    const handleFullscreenChange = () => {
      setState(prev => ({
        ...prev,
        isFullscreen: !!document.fullscreenElement
      }));
    };

    // Add event listeners
    video.addEventListener('timeupdate', handleTimeUpdate);
    video.addEventListener('durationchange', handleDurationChange);
    video.addEventListener('play', handlePlay);
    video.addEventListener('pause', handlePause);
    video.addEventListener('volumechange', handleVolumeChange);
    document.addEventListener('fullscreenchange', handleFullscreenChange);

    // Cleanup
    return () => {
      video.removeEventListener('timeupdate', handleTimeUpdate);
      video.removeEventListener('durationchange', handleDurationChange);
      video.removeEventListener('play', handlePlay);
      video.removeEventListener('pause', handlePause);
      video.removeEventListener('volumechange', handleVolumeChange);
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
    };
  }, [videoRef]);

  return {
    ...state,
    play,
    pause,
    setTime,
    setVolume,
    toggleMute,
    toggleFullscreen,
    setZoom,
    setPan,
    captureFrame
  };
};
```

### **3.5 Zustand Store para Estado Global**

```typescript
// src/store/auth.store.ts
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: 'ADMINISTRATOR' | 'SUPERVISOR' | 'OPERATOR' | 'CLIENT_USER';
  companyId?: string;
  permissions: string[];
}

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  updateUser: (user: Partial<User>) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      login: async (email: string, password: string) => {
        set({ isLoading: true });
        
        try {
          const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
          });

          if (!response.ok) {
            throw new Error('Login failed');
          }

          const data = await response.json();
          
          set({
            user: data.user,
            token: data.token,
            isAuthenticated: true,
            isLoading: false
          });
        } catch (error) {
          set({ isLoading: false });
          throw error;
        }
      },

      logout: () => {
        set({
          user: null,
          token: null,
          isAuthenticated: false
        });
      },

      refreshToken: async () => {
        const { token } = get();
        if (!token) return;

        try {
          const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });

          if (response.ok) {
            const data = await response.json();
            set({ token: data.token });
          } else {
            get().logout();
          }
        } catch (error) {
          get().logout();
        }
      },

      updateUser: (userUpdate: Partial<User>) => {
        set(state => ({
          user: state.user ? { ...state.user, ...userUpdate } : null
        }));
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated
      })
    }
  )
);
```

### **3.6 TanStack Query para Server State**

```typescript
// src/services/events.service.ts (Frontend)
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from './api';

interface SearchEventsParams {
  licensePlate?: string;
  companyId?: string;
  startDate?: string;
  endDate?: string;
  status?: string;
  page?: number;
  limit?: number;
}

interface Event {
  id: string;
  licensePlate: string;
  eventDateTime: string;
  confidence: number;
  company: {
    id: string;
    name: string;
    rut: string;
  };
  status: string;
  hasBasicMetadata: boolean;
  thumbnailPath?: string;
}

// Events Query Keys
export const eventsKeys = {
  all: ['events'] as const,
  lists: () => [...eventsKeys.all, 'list'] as const,
  list: (params: SearchEventsParams) => [...eventsKeys.lists(), params] as const,
  details: () => [...eventsKeys.all, 'detail'] as const,
  detail: (id: string) => [...eventsKeys.details(), id] as const,
};

// Search Events Hook
export const useSearchEvents = (params: SearchEventsParams) => {
  return useQuery({
    queryKey: eventsKeys.list(params),
    queryFn: async () => {
      const response = await api.get('/events', { params });
      return response.data;
    },
    staleTime: 30 * 1000, // 30 seconds
    gcTime: 5 * 60 * 1000, // 5 minutes
    refetchOnWindowFocus: false
  });
};

// Get Event Details Hook
export const useEventDetails = (eventId: string) => {
  return useQuery({
    queryKey: eventsKeys.detail(eventId),
    queryFn: async () => {
      const response = await api.get(`/events/${eventId}`);
      return response.data;
    },
    enabled: !!eventId,
    staleTime: 2 * 60 * 1000, // 2 minutes
  });
};

// Update Event Metadata Mutation
export const useUpdateEventMetadata = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ eventId, metadata }: { eventId: string; metadata: any }) => {
      const response = await api.post(`/events/${eventId}/metadata`, metadata);
      return response.data;
    },
    onSuccess: (data, variables) => {
      // Invalidate and refetch event details
      queryClient.invalidateQueries({
        queryKey: eventsKeys.detail(variables.eventId)
      });
      
      // Update event in lists cache
      queryClient.invalidateQueries({
        queryKey: eventsKeys.lists()
      });
    }
  });
};

// Sync Events from Hikvision Mutation
export const useSyncEvents = () => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ startTime, endTime }: { startTime: string; endTime: string }) => {
      const response = await api.post('/events/sync', { startTime, endTime });
      return response.data;
    },
    onSuccess: () => {
      // Refetch all event lists after sync
      queryClient.invalidateQueries({
        queryKey: eventsKeys.lists()
      });
    }
  });
};
```

---

## 🚀 **4. DEPLOYMENT & DEVOPS CONFIGURATION**

### **4.1 Docker Configuration**

```dockerfile
# Dockerfile - Multi-stage build
# Backend Stage
FROM node:18-alpine AS backend-builder

WORKDIR /app/backend

# Copy package files
COPY backend/package*.json ./
RUN npm ci --only=production

# Copy source
COPY backend/ ./

# Build TypeScript
RUN npm run build

# Frontend Stage  
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy package files
COPY frontend/package*.json ./
RUN npm ci

# Copy source
COPY frontend/ ./

# Build production bundle
RUN npm run build

# Production Stage
FROM node:18-alpine AS production

# Install ffmpeg for video processing
RUN apk add --no-cache ffmpeg

WORKDIR /app

# Copy backend built files
COPY --from=backend-builder /app/backend/dist ./dist
COPY --from=backend-builder /app/backend/node_modules ./node_modules
COPY --from=backend-builder /app/backend/package.json ./

# Copy frontend built files
COPY --from=frontend-builder /app/frontend/dist ./public

# Copy Prisma files
COPY backend/prisma ./prisma

# Create uploads directory
RUN mkdir -p uploads/videos uploads/thumbnails uploads/temp

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

```yaml
# docker-compose.yml - Development Environment
version: '3.8'

services:
  # MySQL Database
  mysql:
    image: mysql:8.0
    container_name: dom_cctv_mysql
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASSWORD}
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
      - ./backend/prisma/init.sql:/docker-entrypoint-initdb.d/init.sql
    command: --default-authentication-plugin=mysql_native_password
    restart: unless-stopped
    networks:
      - dom_cctv_network

  # Redis Cache
  redis:
    image: redis:7-alpine
    container_name: dom_cctv_redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped
    networks:
      - dom_cctv_network

  # Backend API
  backend:
    build:
      context: .
      dockerfile: Dockerfile
      target: backend-builder
    container_name: dom_cctv_backend
    environment:
      NODE_ENV: development
      DATABASE_URL: mysql://${DB_USER}:${DB_PASSWORD}@mysql:3306/${DB_NAME}
      REDIS_URL: redis://redis:6379
      JWT_SECRET: ${JWT_SECRET}
      HIKVISION_BASE_URL: ${HIKVISION_BASE_URL}
      HIKVISION_USERNAME: ${HIKVISION_USERNAME}
      HIKVISION_PASSWORD: ${HIKVISION_PASSWORD}
    ports:
      - "3000:3000"