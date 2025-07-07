# INITIAL.md Template - DOM CCTV Features

## FEATURE:
[Describe específicamente qué funcionalidad quieres construir para el sistema DOM CCTV]

**Ejemplo:** 
"Implementar reproductor de video avanzado con zoom de hasta 10x en resolución 6MP, controles de navegación frame-by-frame, marcadores temporales editables y capacidad de captura de pantalla con anotaciones para análisis detallado de descargas de camiones."

## TECHNICAL CONTEXT:

### Backend Requirements:
- [ ] ¿Necesita nuevos endpoints de API?
- [ ] ¿Requiere cambios en la base de datos?
- [ ] ¿Involucra integración con Hikvision APIs?
- [ ] ¿Necesita nuevos servicios o middleware?

### Frontend Requirements:
- [ ] ¿Requiere nuevos componentes React?
- [ ] ¿Necesita nuevas páginas o rutas?
- [ ] ¿Involucra gestión de estado compleja?
- [ ] ¿Requiere integración con APIs específicas?

### Database Impact:
- [ ] ¿Necesita nuevas tablas o campos?
- [ ] ¿Requiere migración de datos existentes?
- [ ] ¿Afecta el rendimiento de consultas?
- [ ] ¿Necesita nuevos índices?

## EXAMPLES:
[Listar archivos específicos en examples/ que deben ser seguidos como referencia]

**Código relacionado a seguir:**
- `examples/video/video-player-component.tsx` - Patrón base para componentes de video
- `examples/hikvision/stream-handling.js` - Manejo de streams RTSP
- `examples/database/queries.sql` - Patrones de consulta optimizadas
- `examples/authentication/role-permissions.ts` - Control de acceso por roles

## DOCUMENTATION:
[Incluir enlaces a documentación relevante]

### Hikvision APIs:
- [HikCentral OpenAPI Documentation](https://hikvision.com/api-docs)
- [ISAPI Reference Guide](https://hikvision.com/isapi)
- Configuración específica de cámaras DS-2CD3666G2T-IZSY e iDS-2CD7A46G0/P-IZHS

### Technical Documentation:
- [Video.js Documentation](https://videojs.com/getting-started/) - Para reproducción de video
- [React Player Documentation](https://github.com/cookpete/react-player) - Alternativa de reproductor
- [Prisma Documentation](https://www.prisma.io/docs/) - Para cambios en base de datos
- [Material-UI Documentation](https://mui.com/) - Para componentes de interfaz

### Project Documentation:
- `docs/backend_dom_cctv.md` - Arquitectura backend completa
- `docs/frontend_dom_cctv.md` - Especificaciones frontend
- `docs/database_schema_dom_cctv.md` - Esquema de base de datos
- `docs/prd_dom_cctv.md` - Requerimientos del producto

## USER ROLES AFFECTED:
[Especificar qué roles de usuario usarán esta funcionalidad]

- [ ] **OPERATOR** - Usuarios operativos que consultan videos diariamente
- [ ] **ADMINISTRATOR** - Administradores del sistema con acceso completo
- [ ] **CLIENT_USER** - Personal del cliente que agrega metadatos
- [ ] **SUPERVISOR** - Supervisores que generan reportes

## PERMISSIONS REQUIRED:
[Definir qué permisos necesita la funcionalidad]

- [ ] **READ_EVENTS** - Consultar eventos y videos
- [ ] **WRITE_METADATA** - Agregar/editar metadatos de eventos
- [ ] **MANAGE_USERS** - Administrar usuarios del sistema
- [ ] **GENERATE_REPORTS** - Crear y exportar reportes
- [ ] **SYSTEM_CONFIG** - Configurar parámetros del sistema

## HIKVISION INTEGRATION:
[Especificar qué APIs de Hikvision están involucradas]

### HikCentral APIs:
- [ ] `/artemis/api/v1/events/anpr/search` - Búsqueda de eventos ANPR
- [ ] `/artemis/api/v1/video/urls` - Obtener URLs de video para reproducción
- [ ] `/artemis/api/v1/video/picture` - Captura de imágenes instantáneas
- [ ] `/artemis/api/v1/resource/camera/search` - Información de cámaras

### ISAPI Direct:
- [ ] `/ISAPI/Streaming/channels/1/picture` - Captura directa de imagen
- [ ] `/ISAPI/System/deviceInfo` - Información del dispositivo
- [ ] RTSP streams para reproducción en vivo

## PERFORMANCE REQUIREMENTS:
[Especificar requisitos de rendimiento específicos]

### Response Times:
- API endpoints: < 2 segundos
- Video loading: < 3 segundos
- Search results: < 30 segundos
- Database queries: < 1 segundo

### Concurrent Users:
- Soporte mínimo: 50 usuarios concurrentes
- Video streaming: 10 streams simultáneos
- Search operations: 100 búsquedas/minuto

### Storage Impact:
- Video files: Optimización para archivos 6MP
- Database growth: Estimar impacto en GB/mes
- Backup requirements: Estrategia de archivado

## OTHER CONSIDERATIONS:
[Mencionar aspectos específicos que los asistentes comúnmente olvidan]

### CCTV Specific:
- **Frame Rate Handling:** Videos a 15 FPS requieren navegación precisa
- **Resolution Management:** 6MP requiere optimización de memoria
- **Network Bandwidth:** Streams RTSP pueden saturar red local
- **Storage Archiving:** Videos > 120 días deben archivarse automáticamente

### Security Considerations:
- **ANPR Data:** Matrículas son datos sensibles, requieren encriptación
- **Video Access:** Control granular por empresa para usuarios CLIENT_USER
- **Audit Trail:** Todas las acciones deben quedar registradas
- **Session Management:** Timeouts automáticos para sesiones inactivas

### Integration Pitfalls:
- **Hikvision Timeouts:** APIs pueden tardar hasta 30 segundos
- **Camera Disconnections:** Manejar caídas de red elegantemente
- **Concurrent Access:** Múltiples usuarios viendo mismo video
- **Metadata Sync:** Sincronización con sistemas del cliente puede fallar

### User Experience:
- **Loading States:** Indicadores visuales para operaciones lentas
- **Error Recovery:** Opciones de retry para operaciones fallidas
- **Mobile Compatibility:** Diseño responsive para tablets en terreno
- **Keyboard Shortcuts:** Navegación rápida para operadores expertos

### Technical Debt:
- **Code Duplication:** Reutilizar componentes existentes cuando sea posible
- **Error Handling:** Usar patrones establecidos en el proyecto
- **Testing Requirements:** Unit tests y integration tests obligatorios
- **Documentation:** Actualizar docs técnicas con cambios de API

## SUCCESS CRITERIA:
[Definir métricas específicas de éxito]

### Functional:
- [ ] Feature funciona según especificación
- [ ] Integración con Hikvision estable
- [ ] Rendimiento dentro de límites establecidos
- [ ] Tests automáticos pasando

### User Acceptance:
- [ ] Validación con usuarios reales
- [ ] Tiempo de entrenamiento < 30 minutos
- [ ] Reducción en tiempo de operación existente
- [ ] Satisfacción de usuario > 4/5

### Technical:
- [ ] Code coverage > 80%
- [ ] Performance benchmarks cumplidos
- [ ] Security audit passed
- [ ] Documentation actualizada