// examples/tests/api-test-patterns.test.ts
// Patrones estándar para testing de APIs DOM CCTV

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import request from 'supertest';
import { app } from '../src/app';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();

describe('Events API Tests', () => {
  let authToken: string;
  let testUserId: string;
  let testEventId: string;

  beforeEach(async () => {
    // PATRÓN: Setup de datos de prueba
    const testUser = await prisma.user.create({
      data: {
        email: 'test@domcctv.cl',
        password: 'hashedpassword',
        firstName: 'Test',
        lastName: 'User',
        role: 'OPERATOR',
        active: true,
      },
    });
    testUserId = testUser.id;

    // PATRÓN: Generar token JWT para tests
    authToken = jwt.sign(
      { userId: testUserId },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    // PATRÓN: Crear evento de prueba
    const testEvent = await prisma.event.create({
      data: {
        licensePlate: 'TEST123',
        eventDate: new Date(),
        cameraId: 'cam_001',
        cameraName: 'Test Camera',
        videoPath: '/test/video.mp4',
        processed: true,
      },
    });
    testEventId = testEvent.id;
  });

  afterEach(async () => {
    // PATRÓN: Limpieza de datos de prueba
    await prisma.event.deleteMany();
    await prisma.user.deleteMany();
  });

  describe('GET /api/events', () => {
    it('should return events list with valid token', async () => {
      const response = await request(app)
        .get('/api/events')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('success', true);
      expect(response.body.data).toBeInstanceOf(Array);
      expect(response.body.data.length).toBeGreaterThan(0);
    });

    it('should return 401 without token', async () => {
      await request(app)
        .get('/api/events')
        .expect(401);
    });

    it('should filter events by license plate', async () => {
      const response = await request(app)
        .get('/api/events?licensePlate=TEST123')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data).toHaveLength(1);
      expect(response.body.data[0].licensePlate).toBe('TEST123');
    });
  });

  describe('GET /api/events/:id', () => {
    it('should return specific event', async () => {
      const response = await request(app)
        .get(`/api/events/${testEventId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.id).toBe(testEventId);
      expect(response.body.data.licensePlate).toBe('TEST123');
    });

    it('should return 404 for non-existent event', async () => {
      await request(app)
        .get('/api/events/non-existent-id')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('POST /api/events/:id/metadata', () => {
    let testCompanyId: string;

    beforeEach(async () => {
      const testCompany = await prisma.company.create({
        data: {
          rut: '12345678-9',
          name: 'Test Company',
          active: true,
        },
      });
      testCompanyId = testCompany.id;
    });

    it('should add metadata to event', async () => {
      const metadataData = {
        companyId: testCompanyId,
        guideNumber: 'GD-001',
        guideDate: '2025-07-07',
        cargoDescription: 'Test cargo',
        workOrder1: 'WO-001',
        receptionistId: testUserId,
      };

      const response = await request(app)
        .post(`/api/events/${testEventId}/metadata`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(metadataData)
        .expect(201);

      expect(response.body.success).toBe(true);
      
      // Verificar que se guardó en BD
      const savedMetadata = await prisma.metadataEntry.findUnique({
        where: { eventId: testEventId },
      });
      expect(savedMetadata).toBeTruthy();
      expect(savedMetadata?.guideNumber).toBe('GD-001');
    });

    it('should return 400 with invalid data', async () => {
      const invalidData = {
        // Missing required fields
        guideNumber: '',
      };

      await request(app)
        .post(`/api/events/${testEventId}/metadata`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);
    });
  });
});

// PATRÓN: Tests de integración con Hikvision (mocked)
describe('Hikvision Integration Tests', () => {
  let mockHikvisionService: any;

  beforeEach(() => {
    // PATRÓN: Mock del servicio Hikvision
    mockHikvisionService = {
      authenticate: vi.fn().mockResolvedValue('mock-token'),
      searchANPREvents: vi.fn().mockResolvedValue({
        events: [
          {
            eventId: 'hik-001',
            licensePlate: 'ABC123',
            eventTime: new Date().toISOString(),
            cameraId: 'cam_001',
            confidence: 95,
          },
        ],
        totalCount: 1,
      }),
      getVideoPlaybackURL: vi.fn().mockResolvedValue('rtsp://test-url'),
    };
  });

  it('should sync events from Hikvision', async () => {
    // PATRÓN: Test de sincronización con datos mock
    const syncData = {
      startDate: '2025-07-07T00:00:00Z',
      endDate: '2025-07-07T23:59:59Z',
    };

    const response = await request(app)
      .post('/api/events/sync')
      .set('Authorization', `Bearer ${authToken}`)
      .send(syncData)
      .expect(200);

    expect(response.body.success).toBe(true);
    expect(response.body.data.eventsProcessed).toBeGreaterThan(0);
  });
});

// PATRÓN: Tests de rendimiento
describe('Performance Tests', () => {
  it('should handle large dataset queries efficiently', async () => {
    const startTime = Date.now();
    
    const response = await request(app)
      .get('/api/events?limit=1000')
      .set('Authorization', `Bearer ${authToken}`)
      .expect(200);
    
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Verificar que responde en menos de 2 segundos
    expect(responseTime).toBeLessThan(2000);
    expect(response.body.data).toBeInstanceOf(Array);
  });
});