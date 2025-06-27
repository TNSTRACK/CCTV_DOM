# Product Requirements Document (PRD)
## DOM CCTV - Sistema de Videovigilancia y Gestión de Descargas

### 1. Resumen Ejecutivo

**Nombre del Proyecto:** DOM CCTV  
**Versión:** 1.0  
**Fecha:** Junio 2025  
**Tagline:** "Documentación inteligente y trazabilidad completa del proceso de descarga de camiones"

### 2. Descripción del Proyecto

DOM CCTV es una plataforma web integral que documenta mediante videovigilancia el proceso completo de descarga de camiones, desde su llegada hasta el conteo final de mercancías. El sistema utiliza tecnología Hikvision con reconocimiento automático de matrículas (ANPR) y proporciona una interfaz web para gestionar, consultar y enriquecer los videos capturados con metadatos de negocio.

### 3. Problema a Resolver

**Problema Principal:** Las empresas necesitan documentar con precisión visual las tres etapas del proceso de descarga de camiones: estacionamiento, traslado de carga y conteo/pesaje de mercancía, para validar inventarios y resolver disputas comerciales.

**Dolor Actual:**
- Falta de trazabilidad visual en procesos de descarga
- Dificultad para validar conteos manuales
- Tiempo excesivo para localizar eventos específicos
- Imposibilidad de correlacionar videos con datos de negocio

### 4. Audiencia Objetivo

#### Usuario Primario: Operadores de Logística
- **Demografia:** Personal operativo de 25-50 años
- **Objetivos:** Consultar videos específicos por matrícula/fecha, validar descargas
- **Pain Points:** Necesitan acceso rápido a videos sin conocimientos técnicos avanzados

#### Usuario Secundario: Supervisores y Administradores
- **Demografia:** Personal de supervisión y TI de 30-55 años  
- **Objetivos:** Generar reportes, gestionar usuarios, configurar sistema
- **Pain Points:** Requieren herramientas de análisis y control administrativo

#### Usuario Terciario: Personal del Cliente
- **Demografia:** Responsables de recepción de 25-45 años
- **Objetivos:** Agregar datos de guías de despacho y órdenes de trabajo
- **Pain Points:** Interfaz simple para enriquecer información sin acceso a datos sensibles

### 5. Funcionalidades Principales (Priorizadas)

#### Prioridad 1: Búsqueda y Visualización de Videos
- Búsqueda por matrícula, fecha/hora, cliente
- Reproductor de video con zoom y controles avanzados
- Vista de timeline para navegación temporal
- Previsualización de primeros fotogramas

#### Prioridad 2: Herramientas de Análisis de Video
- Zoom en detalles críticos con calidad 6MP
- Marcadores temporales en videos
- Capturas de pantalla con anotaciones
- Navegación frame-by-frame

#### Prioridad 3: Gestión de Metadatos
- Formulario para agregar datos de guías de despacho
- Asociación de múltiples órdenes de trabajo por camión
- Identificación del recepcionista
- Validación de datos requeridos

#### Prioridad 4: Integración con Sistemas del Cliente
- API REST para importar datos automáticamente (Fase 2)
- Webhooks para notificaciones en tiempo real
- Sincronización bidireccional de datos
- Respaldo manual en caso de fallos de API

#### Prioridad 5: Administración de Usuarios
- Gestión de roles: Operador, Administrador, Usuario Cliente, Supervisor
- Control de acceso basado en empresa (para usuarios cliente)
- Registro de actividad y auditoría
- Gestión de sesiones y seguridad

#### Prioridad 6: Dashboard y Reportes
- Dashboard con métricas de actividad diaria
- Reportes por período, cliente, tipo de carga
- Exportación de datos (Excel, PDF, CSV)
- Gráficos de tendencias y estadísticas

### 6. Especificaciones Técnicas del Sistema CCTV

#### Equipamiento
- **10 cámaras totales:**
  - 8x DS-2CD3666G2T-IZSY (documentales, 6MP)
  - 2x iDS-2CD7A46G0/P-IZHS (ANPR)
- **Resolución:** 6 megapíxeles
- **Frame Rate:** 15 FPS
- **Almacenamiento:** 120 días local + archivo en frío (opcional)

#### Integración
- **HikCentral Professional** con OpenAPI para gestión centralizada
- **ISAPI** para comunicación directa con cámaras
- **RTSP** para streaming de video en vivo y playback

### 7. Métricas de Éxito

#### Métricas de Adopción
- **Tasa de adopción:** 90% de operadores usando el sistema en 30 días
- **Eventos documentados:** 100% de camiones registrados automáticamente
- **Tiempo de búsqueda:** < 30 segundos para localizar video específico

#### Métricas de Eficiencia
- **Reducción de tiempo de validación:** 70% menos tiempo vs proceso manual
- **Precisión de datos:** 99% de eventos con metadatos completos
- **Disponibilidad del sistema:** 99.5% uptime

#### Métricas de Negocio
- **Resolución de disputas:** 50% reducción en tiempo de resolución
- **Satisfacción del usuario:** Score > 4.5/5 en usabilidad
- **ROI:** Retorno de inversión positivo en 12 meses

### 8. Supuestos y Riesgos

#### Supuestos
- Red local estable con ancho de banda suficiente (>60 Mbps)
- Personal disponible para capacitación en nuevas herramientas
- Sistema del cliente en desarrollo será compatible con APIs REST
- Almacenamiento local suficiente para 120 días de video 6MP

#### Riesgos y Mitigación
- **Riesgo Alto:** Falla del reconocimiento ANPR
  - *Mitigación:* Sistema de backup con entrada manual de matrículas
- **Riesgo Medio:** Integración tardía con sistema del cliente
  - *Mitigación:* Funcionalidad manual como respaldo permanente
- **Riesgo Medio:** Sobrecarga de almacenamiento
  - *Mitigación:* Estrategia de archivo híbrido local/nube
- **Riesgo Bajo:** Adopción lenta por usuarios
  - *Mitigación:* Interface intuitiva y programa de capacitación

### 9. Cronograma de Desarrollo

#### Fase 1: MVP Funcional (Desarrollo inmediato)
- Sistema de captura automática con ANPR
- Interface web para búsqueda y visualización
- Gestión manual de metadatos
- Roles y permisos básicos

#### Fase 2: Integración Avanzada (Desarrollo posterior)
- API para integración con sistema del cliente
- Dashboard avanzado y reportes
- Optimizaciones de rendimiento
- Features adicionales según feedback

### 10. Criterios de Aceptación

#### Must Have (Crítico)
- Captura automática de video con indexación por matrícula
- Búsqueda rápida por múltiples criterios
- Reproducción de video con calidad 6MP y zoom
- Gestión de usuarios con roles diferenciados

#### Should Have (Importante)
- Dashboard con métricas básicas
- Exportación de reportes
- API preparada para integración futura
- Sistema de auditoría de acciones

#### Could Have (Deseable)
- Notificaciones en tiempo real
- Aplicación móvil para consultas
- Integración con sistemas de almacenamiento en nube
- Analytics avanzados de patrones de tráfico

---

**Documento aprobado por:** [Pendiente]  
**Fecha de última actualización:** Junio 27, 2025