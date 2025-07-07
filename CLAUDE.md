# DOM CCTV - Context Engineering Rules

## PROJECT OVERVIEW
DOM CCTV es un sistema de videovigilancia para documentar procesos de descarga de camiones con reconocimiento automático de matrículas (ANPR) usando tecnología Hikvision.

## TECHNOLOGY STACK

### Backend
- **Node.js 18+** con TypeScript
- **Express.js** como framework web
- **Prisma ORM** con MySQL 8.0+
- **JWT** para autenticación
- **Axios** para integración Hikvision APIs

### Frontend  
- **React 18+** con TypeScript
- **Vite** como bundler
- **Material-UI (MUI) v5** como sistema de diseño
- **TanStack Query** para estado del servidor
- **Zustand** para estado global
- **React Hook Form** para formularios

### Database
- **MySQL 8.0+** como base principal
- **Prisma** para ORM y migraciones
- **Particionamiento** para audit_logs y video_files

### External Integration
- **HikCentral Professional OpenAPI** para gestión centralizada
- **ISAPI Direct** para comunicación directa con cámaras
- **RTSP streams** para reproducción de video

## ARCHITECTURE PRINCIPLES

### Code Organization
- Usar arquitectura por capas: routes -> controllers -> services -> models
- Separar lógica de negocio de controladores
- Componentes React modulares y reutilizables
- Hooks personalizados para lógica compartida

### File Structure Standards
- Backend: `src/` con subdirectorios por responsabilidad
- Frontend: `src/` con componentes, pages, hooks, services
- Usar nombres descriptivos en inglés
- Máximo 300 líneas por archivo de código

### Database Patterns
- Usar UUIDs como primary keys (VARCHAR(30))
- Soft deletes con campo `active`
- Auditoría automática con triggers
- Índices compuestos para búsquedas frecuentes

## HIKVISION INTEGRATION PATTERNS

### Authentication Flow
```typescript
// Siempre usar patrón de token refresh automático
class HikvisionService {
  private accessToken: string | null = null;
  private tokenExpiry: Date | null = null;
  
  async authenticate(): Promise<string> {
    if (this.accessToken && this.tokenExpiry && new Date() < this.tokenExpiry) {
      return this.accessToken;
    }
    // Re-authenticate logic...
  }
}
```

### Error Handling
- Manejar desconexiones de red con retry automático
- Logs detallados para fallos de ANPR
- Fallback manual cuando ANPR falla
- Timeout configurables para todas las llamadas API

### Video Streaming
- Usar proxy para streams RTSP
- Buffer inteligente basado en ancho de banda
- Thumbnails generados automáticamente
- Calidad adaptativa por dispositivo

## SECURITY REQUIREMENTS

### Authentication
- JWT con refresh tokens
- Roles: OPERATOR, ADMINISTRATOR, CLIENT_USER, SUPERVISOR
- Sesiones con expiración automática
- Rate limiting por usuario y endpoint

### Data Protection
- Contraseñas hasheadas con bcrypt
- Variables de entorno para credenciales
- HTTPS obligatorio en producción
- Logs de auditoría para todas las acciones

### Access Control
- Usuarios CLIENT_USER solo ven datos de su empresa
- Filtrado automático por company_id
- Validación de permisos en cada endpoint
- Control de acceso granular en frontend

## PERFORMANCE STANDARDS

### Database Performance
- Consultas < 2 segundos para búsquedas complejas
- Índices para todas las búsquedas frecuentes
- Paginación obligatoria en listas grandes
- Cache para consultas repetitivas

### Video Performance
- Reproducción sin buffering para videos 6MP
- Zoom responsive hasta 10x sin pérdida de calidad
- Carga inicial < 3 segundos
- Thumbnails precargados para navegación rápida

### Frontend Performance
- Lazy loading para componentes pesados
- Code splitting por rutas principales
- Bundle size < 2MB inicial
- Time to Interactive < 3 segundos

## TESTING REQUIREMENTS

### Unit Testing
- Coverage mínimo 80% en servicios críticos
- Mocking de APIs Hikvision en tests
- Tests para todos los hooks personalizados
- Validación de schemas Prisma

### Integration Testing
- Tests end-to-end para flujos críticos
- Simulación de fallos de red
- Tests de rendimiento con datos reales
- Validación de permisos por rol

## ERROR HANDLING PATTERNS

### Backend Errors
```typescript
// Usar middleware de error handling centralizado
app.use((error: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('API Error:', error);
  
  if (error instanceof ValidationError) {
    return res.status(400).json({ error: error.message });
  }
  
  if (error instanceof HikvisionAPIError) {
    return res.status(503).json({ error: 'CCTV system temporarily unavailable' });
  }
  
  res.status(500).json({ error: 'Internal server error' });
});
```

### Frontend Errors
- Error boundaries para componentes de video
- Fallbacks elegantes cuando fallan APIs
- Notificaciones user-friendly con MUI Snackbar
- Retry automático para operaciones críticas

## VIDEO HANDLING BEST PRACTICES

### Video Player Requirements
- Controles personalizados con MUI
- Zoom y pan suaves en resolución 6MP
- Marcadores temporales editables
- Capturas de pantalla con anotaciones
- Navegación frame-by-frame

### Storage Management
- Archivado automático después de 120 días
- Compresión inteligente por uso
- Cleanup de archivos temporales
- Backup incremental de videos críticos

## API DESIGN PATTERNS

### RESTful Endpoints
```
GET /api/events - Búsqueda con filtros
GET /api/events/:id - Evento específico
POST /api/events/:id/metadata - Agregar metadatos
GET /api/events/:id/video - URL de reproducción
POST /api/events/sync - Sincronizar desde Hikvision
```

### Response Format
```typescript
// Formato estándar de respuesta
interface APIResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  pagination?: {
    page: number;
    limit: number;
    total: number;
  };
}
```

## DOCUMENTATION REQUIREMENTS
- Comentarios JSDoc para todas las funciones públicas
- README detallado por módulo
- Ejemplos de uso para APIs críticas
- Changelog para cambios en base de datos

## DEPLOYMENT CONSIDERATIONS
- Docker containers para desarrollo y producción
- Variables de entorno para configuración
- Health checks para servicios críticos
- Monitoring de métricas de negocio

## NEVER DO
- ❌ Hardcodear credenciales de Hikvision
- ❌ Consultas directas a BD desde componentes React
- ❌ Operaciones síncronas bloqueantes en video
- ❌ Logs con información sensible
- ❌ Operaciones sin validación de permisos
- ❌ Commits sin tests para funcionalidades críticas