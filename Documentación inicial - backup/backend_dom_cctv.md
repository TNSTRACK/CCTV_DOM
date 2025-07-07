# Backend Documentation - DOM CCTV
## Arquitectura Node.js/Express con Integración Hikvision

### 1. Stack Tecnológico

#### Framework y Runtime
- **Node.js 18+** LTS
- **Express.js 4.18+** como framework web
- **TypeScript** para type safety
- **ts-node** para desarrollo

#### Base de Datos
- **MySQL 8.0+** como base de datos principal
- **Prisma ORM** para gestión de base de datos y migraciones
- **Connection pooling** para optimización de conexiones

#### Autenticación y Seguridad
- **JWT (jsonwebtoken)** para autenticación
- **bcryptjs** para hash de contraseñas
- **helmet** para security headers
- **cors** para control de CORS
- **express-rate-limit** para limitación de requests

#### Integración Externa
- **axios** para comunicación con APIs Hikvision
- **multer** para manejo de archivos (futuro)
- **node-cron** para tareas programadas

### 2. Arquitectura del Proyecto

#### Estructura de Directorios
```
src/
├── config/              # Configuraciones
│   ├── database.ts      # Configuración de BD
│   ├── auth.ts          # Configuración JWT
│   └── hikvision.ts     # Configuración APIs Hikvision
├── controllers/         # Controladores de rutas
│   ├── auth.controller.ts
│   ├── events.controller.ts
│   ├── videos.controller.ts
│   ├── metadata.controller.ts
│   ├── users.controller.ts
│   └── reports.controller.ts
├── middleware/          # Middlewares
│   ├── auth.middleware.ts
│   ├── validation.middleware.ts
│   ├── error.middleware.ts
│   └── logger.middleware.ts
├── models/              # Modelos de datos (Prisma)
├── routes/              # Definición de rutas
│   ├── auth.routes.ts
│   ├── events.routes.ts
│   ├── videos.routes.ts
│   ├── metadata.routes.ts
│   ├── users.routes.ts
│   └── reports.routes.ts
├── services/            # Lógica de negocio
│   ├── hikvision.service.ts
│   ├── events.service.ts
│   ├── videos.service.ts
│   ├── metadata.service.ts
│   ├── users.service.ts
│   └── reports.service.ts
├── types/               # Definiciones TypeScript
├── utils/               # Utilidades
├── validators/          # Esquemas de validación
└── app.ts              # Configuración principal
```

### 3. Configuración de Base de Datos

#### Esquema Prisma

```prisma
// schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "mysql"
  url      = env("DATABASE_URL")
}

model User {
  id        String   @id @default(cuid())
  email     String   @unique
  password  String
  firstName String
  lastName  String
  role      UserRole
  companyId String?
  company   Company? @relation(fields: [companyId], references: [id])
  active    Boolean  @default(true)
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
  
  // Relaciones
  metadataEntries MetadataEntry[]
  auditLogs       AuditLog[]
  
  @@map("users")
}

model Company {
  id          String @id @default(cuid())
  rut         String @unique
  name        String
  address     String?
  contactInfo String?
  active      Boolean @default(true)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt
  
  // Relaciones
  users           User[]
  metadataEntries MetadataEntry[]
  
  @@map("companies")
}

model Event {
  id            String    @id @default(cuid())
  licensePlate  String    // Matrícula detectada por ANPR
  eventDate     DateTime  // Fecha/hora del evento
  cameraId      String    // ID de la cámara que capturó
  cameraName    String    // Nombre descriptivo de la cámara
  videoPath     String    // Ruta del archivo de video
  thumbnailPath String?   // Ruta de la imagen de preview
  processed     Boolean   @default(false)
  createdAt     DateTime  @default(now())
  updatedAt     DateTime  @updatedAt
  
  // Relaciones
  metadata MetadataEntry?
  
  @@index([licensePlate])
  @@index([eventDate])
  @@index([cameraId])
  @@map("events")
}

model MetadataEntry {
  id                    String    @id @default(cuid())
  eventId               String    @unique
  event                 Event     @relation(fields: [eventId], references: [id], onDelete: Cascade)
  
  // Datos de la empresa
  companyId             String
  company               Company   @relation(fields: [companyId], references: [id])
  
  // Datos de la guía de despacho
  guideNumber           String    // Número de Guía de Despacho
  guideDate             DateTime  // Fecha de la guía de despacho
  cargoDescription      String    // Descripción del contenido
  
  // Órdenes de trabajo
  workOrder1            String    // Orden de Trabajo principal
  workOrder2            String?   // Orden de Trabajo secundaria (opcional)
  
  // Recepcionista
  receptionistId        String
  receptionist          User      @relation(fields: [receptionistId], references: [id])
  
  // Metadatos de creación
  createdAt             DateTime  @default(now())
  updatedAt             DateTime  @updatedAt
  
  @@map("metadata_entries")
}

model AuditLog {
  id        String     @id @default(cuid())
  userId    String
  user      User       @relation(fields: [userId], references: [id])
  action    AuditAction
  entityType String    // "event", "metadata", "user", etc.
  entityId   String
  oldValues  Json?
  newValues  Json?
  ipAddress  String?
  userAgent  String?
  createdAt  DateTime  @default(now())
  
  @@map("audit_logs")
}

enum UserRole {
  OPERATOR
  ADMINISTRATOR
  CLIENT_USER
  SUPERVISOR
}

enum AuditAction {
  CREATE
  UPDATE
  DELETE
  VIEW
  LOGIN
  LOGOUT
}
```

### 4. Integración con Hikvision

#### HikCentral OpenAPI Service

```typescript
// services/hikvision.service.ts
import axios, { AxiosInstance } from 'axios';

interface HikvisionConfig {
  baseURL: string;
  appKey: string;
  appSecret: string;
  timeout: number;
}

export class HikvisionService {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private tokenExpiry: Date | null = null;

  constructor(private config: HikvisionConfig) {
    this.client = axios.create({
      baseURL: config.baseURL,
      timeout: config.timeout,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  // Autenticación con HikCentral
  async authenticate(): Promise<string> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.accessToken;
    }

    const response = await this.client.post('/artemis/api/v1/oauth/token', {
      grant_type: 'client_credentials',
      scope: 'read write',
    }, {
      auth: {
        username: this.config.appKey,
        password: this.config.appSecret,
      },
    });

    this.accessToken = response.data.access_token;
    this.tokenExpiry = new Date(Date.now() + (response.data.expires_in * 1000));
    
    return this.accessToken;
  }

  // Búsqueda de eventos por ANPR
  async searchANPREvents(params: {
    startTime: string;
    endTime: string;
    licensePlate?: string;
    cameraIds?: string[];
  }): Promise<ANPREvent[]> {
    const token = await this.authenticate();
    
    const response = await this.client.post('/artemis/api/v1/events/anpr/search', {
      pageNo: 1,
      pageSize: 1000,
      startTime: params.startTime,
      endTime: params.endTime,
      licensePlate: params.licensePlate,
      cameraIndexCodes: params.cameraIds,
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    return response.data.data.list;
  }

  // Obtener URL de video para reproducción
  async getVideoPlaybackURL(params: {
    cameraId: string;
    startTime: string;
    endTime: string;
  }): Promise<string> {
    const token = await this.authenticate();
    
    const response = await this.client.post('/artemis/api/v1/video/urls', {
      cameraIndexCode: params.cameraId,
      recordType: 0, // Grabación normal
      streamType: 0, // Stream principal
      protocol: 'rtsp',
      startTime: params.startTime,
      endTime: params.endTime,
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    return response.data.data.url;
  }

  // Obtener lista de cámaras
  async getCameras(): Promise<Camera[]> {
    const token = await this.authenticate();
    
    const response = await this.client.post('/artemis/api/v1/resource/camera/search', {
      pageNo: 1,
      pageSize: 1000,
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    return response.data.data.list;
  }

  // Capturar imagen instantánea
  async captureSnapshot(cameraId: string): Promise<Buffer> {
    const token = await this.authenticate();
    
    const response = await this.client.post('/artemis/api/v1/video/picture', {
      cameraIndexCode: cameraId,
      pictureType: 1, // Imagen actual
    }, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
      responseType: 'arraybuffer',
    });

    return Buffer.from(response.data);
  }
}
```

#### ISAPI Direct Communication Service

```typescript
// services/isapi.service.ts
export class ISAPIService {
  private cameras: Map<string, CameraConfig> = new Map();

  constructor(cameraConfigs: CameraConfig[]) {
    cameraConfigs.forEach(config => {
      this.cameras.set(config.id, config);
    });
  }

  // Captura directa de imagen ANPR
  async captureANPRImage(cameraId: string): Promise<Buffer> {
    const camera = this.cameras.get(cameraId);
    if (!camera) throw new Error('Camera not found');

    const url = `http://${camera.ip}/ISAPI/Streaming/channels/1/picture`;
    const response = await axios.get(url, {
      auth: {
        username: camera.username,
        password: camera.password,
      },
      responseType: 'arraybuffer',
      timeout: 10000,
    });

    return Buffer.from(response.data);
  }

  // Obtener información del dispositivo
  async getDeviceInfo(cameraId: string): Promise<DeviceInfo> {
    const camera = this.cameras.get(cameraId);
    if (!camera) throw new Error('Camera not found');

    const url = `http://${camera.ip}/ISAPI/System/deviceInfo`;
    const response = await axios.get(url, {
      auth: {
        username: camera.username,
        password: camera.password,
      },
      timeout: 5000,
    });

    return this.parseXMLDeviceInfo(response.data);
  }

  // Obtener stream RTSP directo
  getRTSPUrl(cameraId: string, streamType: 'main' | 'sub' = 'main'): string {
    const camera = this.cameras.get(cameraId);
    if (!camera) throw new Error('Camera not found');

    const channelId = streamType === 'main' ? '101' : '102';
    return `rtsp://${camera.username}:${camera.password}@${camera.ip}:554/ISAPI/Streaming/Channels/${channelId}`;
  }
}
```

### 5. Controladores de API

#### Events Controller

```typescript
// controllers/events.controller.ts
import { Request, Response } from 'express';
import { EventsService } from '../services/events.service';
import { AuthenticatedRequest } from '../types/auth.types';

export class EventsController {
  constructor(private eventsService: EventsService) {}

  // Búsqueda de eventos con filtros
  async searchEvents(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const filters = req.query as EventSearchFilters;
      const userRole = req.user!.role;
      const companyId = req.user!.companyId;

      // Filtrar por empresa si es usuario cliente
      if (userRole === 'CLIENT_USER' && companyId) {
        filters.companyId = companyId;
      }

      const events = await this.eventsService.searchEvents(filters);
      res.json({
        success: true,
        data: events,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  // Obtener evento específico
  async getEvent(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const event = await this.eventsService.getEventById(id);

      if (!event) {
        res.status(404).json({
          success: false,
          error: 'Event not found',
        });
        return;
      }

      // Verificar permisos para usuarios cliente
      if (req.user!.role === 'CLIENT_USER') {
        const hasAccess = await this.eventsService.userHasAccessToEvent(
          req.user!.id,
          event.id
        );
        if (!hasAccess) {
          res.status(403).json({
            success: false,
            error: 'Access denied',
          });
          return;
        }
      }

      res.json({
        success: true,
        data: event,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  // Sincronizar eventos desde Hikvision
  async syncEvents(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { startDate, endDate } = req.body;
      const result = await this.eventsService.syncEventsFromHikvision({
        startDate: new Date(startDate),
        endDate: new Date(endDate),
      });

      res.json({
        success: true,
        data: {
          eventsProcessed: result.processed,
          eventsAdded: result.added,
          eventsUpdated: result.updated,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
}
```

#### Videos Controller

```typescript
// controllers/videos.controller.ts
export class VideosController {
  constructor(
    private hikvisionService: HikvisionService,
    private isapiService: ISAPIService
  ) {}

  // Proxy para reproducción de video
  async getVideoStream(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { eventId } = req.params;
      const event = await prisma.event.findUnique({
        where: { id: eventId },
      });

      if (!event) {
        res.status(404).json({ error: 'Event not found' });
        return;
      }

      // Verificar permisos
      if (req.user!.role === 'CLIENT_USER') {
        const hasAccess = await this.checkEventAccess(req.user!.id, eventId);
        if (!hasAccess) {
          res.status(403).json({ error: 'Access denied' });
          return;
        }
      }

      // Obtener URL de video desde Hikvision
      const videoUrl = await this.hikvisionService.getVideoPlaybackURL({
        cameraId: event.cameraId,
        startTime: event.eventDate.toISOString(),
        endTime: new Date(event.eventDate.getTime() + 300000).toISOString(), // 5 min
      });

      res.json({
        success: true,
        data: { url: videoUrl },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }

  // Captura de imagen de video
  async captureSnapshot(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { eventId } = req.params;
      const { timestamp } = req.query;

      const event = await prisma.event.findUnique({
        where: { id: eventId },
      });

      if (!event) {
        res.status(404).json({ error: 'Event not found' });
        return;
      }

      const imageBuffer = await this.isapiService.captureANPRImage(event.cameraId);
      
      res.setHeader('Content-Type', 'image/jpeg');
      res.setHeader('Content-Length', imageBuffer.length);
      res.send(imageBuffer);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  // Obtener thumbnail de evento
  async getThumbnail(req: Request, res: Response): Promise<void> {
    try {
      const { eventId } = req.params;
      const event = await prisma.event.findUnique({
        where: { id: eventId },
      });

      if (!event || !event.thumbnailPath) {
        res.status(404).json({ error: 'Thumbnail not found' });
        return;
      }

      const thumbnailPath = path.join(process.env.THUMBNAILS_DIR!, event.thumbnailPath);
      res.sendFile(thumbnailPath);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}
```

### 6. Servicios de Negocio

#### Events Service

```typescript
// services/events.service.ts
export class EventsService {
  constructor(
    private hikvisionService: HikvisionService,
    private auditService: AuditService
  ) {}

  async searchEvents(filters: EventSearchFilters): Promise<EventWithMetadata[]> {
    const whereClause: any = {};

    // Filtros de búsqueda
    if (filters.licensePlate) {
      whereClause.licensePlate = {
        contains: filters.licensePlate,
        mode: 'insensitive',
      };
    }

    if (filters.startDate && filters.endDate) {
      whereClause.eventDate = {
        gte: new Date(filters.startDate),
        lte: new Date(filters.endDate),
      };
    }

    if (filters.cameraId) {
      whereClause.cameraId = filters.cameraId;
    }

    if (filters.companyId) {
      whereClause.metadata = {
        companyId: filters.companyId,
      };
    }

    const events = await prisma.event.findMany({
      where: whereClause,
      include: {
        metadata: {
          include: {
            company: true,
            receptionist: {
              select: {
                id: true,
                firstName: true,
                lastName: true,
              },
            },
          },
        },
      },
      orderBy: {
        eventDate: 'desc',
      },
      take: filters.limit || 50,
      skip: filters.offset || 0,
    });

    return events;
  }

  async syncEventsFromHikvision(params: {
    startDate: Date;
    endDate: Date;
  }): Promise<{ processed: number; added: number; updated: number }> {
    const anprEvents = await this.hikvisionService.searchANPREvents({
      startTime: params.startDate.toISOString(),
      endTime: params.endDate.toISOString(),
    });

    let processed = 0;
    let added = 0;
    let updated = 0;

    for (const anprEvent of anprEvents) {
      processed++;

      const existingEvent = await prisma.event.findFirst({
        where: {
          licensePlate: anprEvent.licensePlate,
          eventDate: new Date(anprEvent.eventTime),
          cameraId: anprEvent.cameraId,
        },
      });

      if (existingEvent) {
        // Actualizar si es necesario
        await prisma.event.update({
          where: { id: existingEvent.id },
          data: {
            videoPath: anprEvent.videoPath,
            processed: true,
          },
        });
        updated++;
      } else {
        // Crear nuevo evento
        await prisma.event.create({
          data: {
            licensePlate: anprEvent.licensePlate,
            eventDate: new Date(anprEvent.eventTime),
            cameraId: anprEvent.cameraId,
            cameraName: anprEvent.cameraName,
            videoPath: anprEvent.videoPath,
            thumbnailPath: await this.generateThumbnail(anprEvent),
            processed: true,
          },
        });
        added++;
      }
    }

    return { processed, added, updated };
  }

  private async generateThumbnail(anprEvent: ANPREvent): Promise<string> {
    // Lógica para generar thumbnail desde el video
    // Esto podría usar FFmpeg o captura directa de la cámara
    return `thumbnails/${anprEvent.cameraId}_${Date.now()}.jpg`;
  }
}
```

### 7. Middleware de Autenticación

```typescript
// middleware/auth.middleware.ts
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: UserRole;
    companyId?: string;
  };
}

export const authenticateToken = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Access token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
    
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        role: true,
        companyId: true,
        active: true,
      },
    });

    if (!user || !user.active) {
      res.status(401).json({ error: 'Invalid or inactive user' });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

export const requireRole = (roles: UserRole[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(403).json({ error: 'Insufficient permissions' });
      return;
    }
    next();
  };
};
```

### 8. Validación de Datos

```typescript
// validators/metadata.validator.ts
import { z } from 'zod';

export const metadataSchema = z.object({
  eventId: z.string().cuid(),
  companyId: z.string().cuid(),
  guideNumber: z.string().min(1, 'Guide number is required'),
  guideDate: z.string().datetime(),
  cargoDescription: z.string().min(1, 'Cargo description is required'),
  workOrder1: z.string().min(1, 'Work order is required'),
  workOrder2: z.string().optional(),
  receptionistId: z.string().cuid(),
});

export const eventSearchSchema = z.object({
  licensePlate: z.string().optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  cameraId: z.string().optional(),
  companyId: z.string().cuid().optional(),
  limit: z.number().min(1).max(100).optional(),
  offset: z.number().min(0).optional(),
});
```

### 9. Configuración del Servidor

```typescript
// app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';

// Routes
import authRoutes from './routes/auth.routes';
import eventsRoutes from './routes/events.routes';
import videosRoutes from './routes/videos.routes';
import metadataRoutes from './routes/metadata.routes';
import usersRoutes from './routes/users.routes';
import reportsRoutes from './routes/reports.routes';

// Middleware
import { errorHandler } from './middleware/error.middleware';
import { logger } from './middleware/logger.middleware';

const app = express();
export const prisma = new PrismaClient();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Logging
app.use(logger);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/events', eventsRoutes);
app.use('/api/videos', videosRoutes);
app.use('/api/metadata', metadataRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/reports', reportsRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling
app.use(errorHandler);

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;
```

### 10. Variables de Entorno

```env
# Database
DATABASE_URL="mysql://user:password@localhost:3306/dom_cctv"

# JWT
JWT_SECRET="your-super-secret-jwt-key"
JWT_EXPIRES_IN="24h"

# Hikvision API
HIKVISION_API_URL="https://hikcentralpro-ip"
HIKVISION_APP_KEY="your-app-key"
HIKVISION_APP_SECRET="your-app-secret"

# Server
PORT=3001
NODE_ENV="production"
FRONTEND_URL="http://localhost:3000"

# File Storage
VIDEOS_DIR="/var/videos"
THUMBNAILS_DIR="/var/thumbnails"
TEMP_DIR="/tmp"

# Logging
LOG_LEVEL="info"
LOG_FILE="/var/log/dom-cctv.log"
```

### 11. Tareas Programadas

```typescript
// services/scheduler.service.ts
import cron from 'node-cron';
import { EventsService } from './events.service';

export class SchedulerService {
  constructor(private eventsService: EventsService) {}

  start(): void {
    // Sincronización cada hora durante horario laboral
    cron.schedule('0 8-18 * * 1-6', async () => {
      console.log('Starting scheduled sync...');
      await this.syncRecentEvents();
    });

    // Limpieza de archivos temporales diaria
    cron.schedule('0 2 * * *', async () => {
      console.log('Starting cleanup...');
      await this.cleanupTempFiles();
    });

    // Generación de thumbnails pendientes
    cron.schedule('*/15 * * * *', async () => {
      await this.generatePendingThumbnails();
    });
  }

  private async syncRecentEvents(): Promise<void> {
    const endDate = new Date();
    const startDate = new Date(endDate.getTime() - 2 * 60 * 60 * 1000); // 2 horas atrás

    try {
      await this.eventsService.syncEventsFromHikvision({
        startDate,
        endDate,
      });
      console.log('Sync completed successfully');
    } catch (error) {
      console.error('Sync failed:', error);
    }
  }
}
```

---

**Documentación técnica completa para backend Node.js/Express con integración completa Hikvision OpenAPI e ISAPI**