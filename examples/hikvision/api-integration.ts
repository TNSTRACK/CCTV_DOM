// examples/hikvision/api-integration.ts
// Patrón estándar para integración con APIs Hikvision

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
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // PATRÓN: Autenticación con token refresh automático
  async authenticate(): Promise<string> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.accessToken;
    }

    try {
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
    } catch (error) {
      throw new Error(`Hikvision authentication failed: ${error.message}`);
    }
  }

  // PATRÓN: Búsqueda de eventos ANPR con paginación
  async searchANPREvents(params: {
    startTime: string;
    endTime: string;
    licensePlate?: string;
    cameraIds?: string[];
    pageNo?: number;
    pageSize?: number;
  }): Promise<{ events: ANPREvent[]; totalCount: number }> {
    const token = await this.authenticate();
    
    try {
      const response = await this.client.post('/artemis/api/v1/events/anpr/search', {
        pageNo: params.pageNo || 1,
        pageSize: params.pageSize || 50,
        startTime: params.startTime,
        endTime: params.endTime,
        licensePlate: params.licensePlate,
        cameraIndexCodes: params.cameraIds,
      }, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      return {
        events: response.data.data.list || [],
        totalCount: response.data.data.total || 0,
      };
    } catch (error) {
      throw new Error(`ANPR search failed: ${error.message}`);
    }
  }

  // PATRÓN: Obtener URL de video para reproducción
  async getVideoPlaybackURL(params: {
    cameraId: string;
    startTime: string;
    endTime: string;
  }): Promise<string> {
    const token = await this.authenticate();
    
    try {
      const response = await this.client.post('/artemis/api/v1/video/urls', {
        cameraIndexCode: params.cameraId,
        recordType: 0, // Grabación normal
        streamType: 0, // Stream principal
        protocol: 'rtsp',
        startTime: params.startTime,
        endTime: params.endTime,
      }, {
        headers: { 'Authorization': `Bearer ${token}` },
      });

      return response.data.data.url;
    } catch (error) {
      throw new Error(`Video URL retrieval failed: ${error.message}`);
    }
  }
}

interface ANPREvent {
  eventId: string;
  licensePlate: string;
  eventTime: string;
  cameraId: string;
  cameraName: string;
  confidence: number;
  videoPath: string;
}