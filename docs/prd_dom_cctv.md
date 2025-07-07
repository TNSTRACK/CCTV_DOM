# Product Requirements Document (PRD) - DOM CCTV
## Sistema de Videovigilancia para Devolución de Encofrados en Arriendo

### **Metadatos del Documento**
- **Versión:** 2.0 - Context Engineering Optimized
- **Fecha:** 07/07/2025
- **Metodología:** Context Engineering Approach
- **Cliente:** DOM (Empresa Arrendadora de Encofrados)
- **Sistema UI:** Material Design v5
- **Arquitectura:** Bifásica (Core + Avanzada)

---

## 🎯 **1. RESUMEN EJECUTIVO ORIENTADO A CONTEXTO**

### **Vision Statement**
DOM CCTV es una plataforma web progresiva que documenta mediante videovigilancia inteligente la llegada y descarga de camiones con encofrados arrendados, utilizando reconocimiento automático de matrículas (ANPR) con tecnología Hikvision para crear un sistema de trazabilidad visual completo.

### **Tagline del Producto**
*"Documentación inteligente y trazabilidad completa del proceso de devolución de encofrados"*

### **Enfoque Bifásico Validado**
- **FASE 1 - CORE ESENCIAL (MVP):** Documentación automática y búsqueda inteligente de videos
- **FASE 2 - GESTIÓN AVANZADA:** Conteo detallado, validación de inventarios y gestión de discrepancias

---

## 📊 **2. MODELO DE DATOS REFINADO CON CONTEXT ENGINEERING**

### **2.1. Entidades Core - FASE 1 (Rediseñadas según feedback)**

#### **Event (Evento ANPR de Llegada de Camión)**
```typescript
interface TruckArrivalEvent {
  id: string;                    // UUID único del evento
  licensePlate: string;          // Matrícula leída por ANPR
  eventDateTime: Date;           // Fecha/hora de detección ANPR
  confidence: number;            // Confianza ANPR (0-100%)
  
  // MEJORA: Entidad Company como FK desde el inicio
  companyId: string;             // FK a Company - CRÍTICO para filtros
  
  // Origen ANPR con redundancia mejorada
  primaryCamera: {
    id: string;                  // ID cámara ANPR principal
    image: string;               // URL imagen capturada
    confidence: number;          // Confianza lectura principal
    plateReading: string;        // Lectura principal de matrícula
  };
  
  secondaryCamera?: {
    id: string;                  // ID cámara ANPR secundaria
    image: string;               // URL imagen capturada  
    confidence: number;          // Confianza lectura secundaria
    plateReading: string;        // Lectura secundaria (puede diferir)
  };
  
  // Estados más granulares
  status: EventStatus;
  hasBasicMetadata: boolean;     
  readyForPhase2: boolean;       // Flag para transición a FASE 2
  
  // Videos documentales del proceso
  documentaryVideos: VideoFile[]; 
  thumbnailPath?: string;        
  
  // Metadatos del sistema mejorados
  createdAt: Date;
  updatedAt: Date;
  processedAt?: Date;
  
  // ÍNDICES REQUERIDOS para búsquedas <2''
  // INDEX idx_event_license_plate (licensePlate)
  // INDEX idx_event_company_date (companyId, eventDateTime)
  // INDEX idx_event_status (status, hasBasicMetadata)
}

enum EventStatus {
  DETECTED = 'DETECTED',         // Detectado por ANPR
  DOCUMENTED = 'DOCUMENTED',     // Con metadatos básicos
  VALIDATED = 'VALIDATED',       // Revisado por supervisor
  ARCHIVED = 'ARCHIVED'          // Archivado tras 120 días
}
```

#### **BasicEventMetadata (Rediseñado según comentarios)**
```typescript
interface BasicEventMetadata {
  id: string;
  eventId: string;               // FK a Event
  
  // MEJORA: Company como entidad separada con FK
  companyId: string;             // FK a Company tabla
  
  // Información de la devolución
  basicReturnInfo: {
    guideNumber?: string;        // Número guía de despacho
    guideDate?: Date;            // Fecha de la guía
    originProject?: string;      // Proyecto de origen
    cargoDescription?: string;   // Descripción general
    observations?: string;       // Observaciones generales
  };
  
  // MEJORA: Personal que registra con FK a User
  registeredBy: {
    userId: string;              // FK a User - MEJORADO
    timestamp: Date;
  };
  
  // Auditoría mejorada
  createdBy: string;             // FK a User
  createdAt: Date;
  updatedAt: Date;
  lastModifiedBy?: string;       // FK a User - para auditoría
  
  // Control de transición a FASE 2
  readyForDetailedProcessing: boolean;
  
  // ÍNDICE COMPUESTO para búsquedas
  // INDEX idx_metadata_company_guide (companyId, guideNumber)
}
```

#### **Company (Entidad Empresa Rediseñada)**
```typescript
interface Company {
  // MEJORA: ID como string, RUT como campo único separado
  id: string;                    // UUID - Primary Key
  rut: string;                   // RUT único chileno (formato: 12345678-9) - UNIQUE INDEX
  
  // Información básica
  name: string;                  // Razón social
  businessName?: string;         // Nombre comercial
  
  // Información de contacto
  address: string;
  city: string;
  region: string;
  phone: string;
  email: string;
  
  // Contacto principal
  primaryContact: {
    name: string;
    position: string;
    phone: string;
    email: string;
  };
  
  // Estado y configuración básica
  isActive: boolean;
  
  // FASE 2 - Configuración avanzada (tabla separada)
  advancedConfigId?: string;     // FK a CompanyAdvancedConfig
  
  // Auditoría
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;             // FK a User
  
  // ÍNDICES CRÍTICOS
  // UNIQUE INDEX idx_company_rut (rut)
  // INDEX idx_company_active (isActive)
  // INDEX idx_company_name (name) - para búsquedas por nombre
}

// FASE 2 - Configuración avanzada en tabla separada
interface CompanyAdvancedConfig {
  id: string;
  companyId: string;             // FK a Company
  
  defaultReturnPeriod: number;   // Días estándar de arriendo
  allowedGracePeriod: number;    // Días de gracia
  requiresApproval: boolean;     // Aprobación para discrepancias
  autoNotifications: boolean;    // Notificaciones automáticas
  
  // MEJORA: creditStatus como enum para control
  creditStatus: CreditStatus;
  
  createdAt: Date;
  updatedAt: Date;
}

enum CreditStatus {
  EXCELLENT = 'EXCELLENT',
  GOOD = 'GOOD',
  WARNING = 'WARNING',
  BLOCKED = 'BLOCKED'
}
```

#### **User (Sistema de Usuarios y Permisos Rediseñado)**
```typescript
interface User {
  id: string;                    // UUID Primary Key
  
  // MEJORA: Email como único pero ID separado para flexibilidad
  email: string;                 // UNIQUE INDEX - único
  password: string;              // Hash bcrypt
  
  // Información personal con validación de unicidad
  firstName: string;
  lastName: string;
  phone?: string;
  
  // MEJORA: fullName computado y único por empresa
  // CONSTRAINT UNIQUE (firstName, lastName, companyId) WHERE companyId IS NOT NULL
  
  // Roles y permisos principales
  role: UserRole;
  
  // MEJORA: Permisos en tabla separada para flexibilidad
  // Relación muchos a muchos con UserPermissions
  
  // Asociación empresarial
  companyId?: string;            // FK a Company (NULL para usuarios internos)
  department?: string;
  position?: string;
  
  // Estado y seguridad
  isActive: boolean;
  emailVerified: boolean;
  lastLogin?: Date;
  failedLoginAttempts: number;
  lockedUntil?: Date;
  
  // MEJORA: Preferencias en tabla separada
  preferencesId?: string;        // FK a UserPreferences
  
  // FASE 2: Perfil avanzado en tabla separada
  advancedProfileId?: string;    // FK a UserAdvancedProfile
  
  // Auditoría
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;            // FK a User
  
  // ÍNDICES CRÍTICOS
  // UNIQUE INDEX idx_user_email (email)
  // INDEX idx_user_company (companyId) WHERE companyId IS NOT NULL
  // INDEX idx_user_active_role (isActive, role)
}

// MEJORA: Tabla separada para preferencias
interface UserPreferences {
  id: string;
  userId: string;                // FK a User
  
  language: Language;
  timezone: string;
  theme: Theme;
  
  // Configuraciones específicas de UI
  defaultPageSize: number;
  videoQuality: VideoQuality;
  autoPlay: boolean;
  
  updatedAt: Date;
}

enum Language {
  ES = 'es',
  EN = 'en'
}

enum Theme {
  LIGHT = 'light',
  DARK = 'dark',
  AUTO = 'auto'
}

enum VideoQuality {
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  AUTO = 'auto'
}

// MEJORA: Tabla separada para permisos con relación muchos a muchos
interface UserPermission {
  id: string;
  userId: string;               // FK a User
  permission: Permission;
  grantedAt: Date;
  grantedBy: string;            // FK a User
  expiresAt?: Date;             // Para permisos temporales
  
  // ÍNDICE COMPUESTO
  // INDEX idx_user_permission (userId, permission)
}

// FASE 2: Perfil avanzado en tabla separada
interface UserAdvancedProfile {
  id: string;
  userId: string;               // FK a User
  
  // MEJORA: certificationLevel como enum
  certificationLevel: CertificationLevel;
  canApproveDiscrepancies: boolean;
  maxDiscrepancyValue: number;
  specializedTypes: string[];   // JSON array de tipos de encofrados
  
  // Notificaciones avanzadas (podría ser tabla separada también)
  advancedNotifications: {
    returnReminders: boolean;
    discrepancyAlerts: boolean;
    approvalRequests: boolean;
  };
  
  createdAt: Date;
  updatedAt: Date;
}

enum CertificationLevel {
  BASIC = 'BASIC',
  INTERMEDIATE = 'INTERMEDIATE',
  EXPERT = 'EXPERT',
  MASTER = 'MASTER'
}

// Roles básicos FASE 1
enum UserRole {
  ADMINISTRATOR = 'ADMINISTRATOR',
  SUPERVISOR = 'SUPERVISOR', 
  OPERATOR = 'OPERATOR',
  CLIENT_USER = 'CLIENT_USER'
}

// MEJORA: Permisos como enum con jerarquía clara
enum Permission {
  // === EVENTOS BÁSICOS ===
  READ_EVENTS = 'READ_EVENTS',
  WRITE_BASIC_METADATA = 'WRITE_BASIC_METADATA',
  EDIT_OWN_METADATA = 'EDIT_OWN_METADATA',
  DELETE_EVENTS = 'DELETE_EVENTS',
  
  // === VIDEOS ===
  VIEW_VIDEOS = 'VIEW_VIDEOS',
  DOWNLOAD_VIDEOS = 'DOWNLOAD_VIDEOS',
  EXPORT_VIDEO_SEGMENTS = 'EXPORT_VIDEO_SEGMENTS',
  
  // === BÚSQUEDA ===
  SEARCH_ALL_COMPANIES = 'SEARCH_ALL_COMPANIES',
  SEARCH_OWN_COMPANY = 'SEARCH_OWN_COMPANY',
  ADVANCED_SEARCH = 'ADVANCED_SEARCH',
  
  // === ADMINISTRACIÓN ===
  MANAGE_USERS = 'MANAGE_USERS',
  MANAGE_COMPANIES = 'MANAGE_COMPANIES',
  SYSTEM_CONFIG = 'SYSTEM_CONFIG',
  VIEW_AUDIT_LOGS = 'VIEW_AUDIT_LOGS',
  
  // === REPORTES ===
  GENERATE_BASIC_REPORTS = 'GENERATE_BASIC_REPORTS',
  GENERATE_DETAILED_REPORTS = 'GENERATE_DETAILED_REPORTS',
  EXPORT_DATA = 'EXPORT_DATA',
  SCHEDULE_REPORTS = 'SCHEDULE_REPORTS'
}

// MEJORA: Jerarquía de permisos definida
// DOWNLOAD_VIDEOS implica VIEW_VIDEOS
// SEARCH_ALL_COMPANIES implica SEARCH_OWN_COMPANY
// MANAGE_USERS implica VIEW_AUDIT_LOGS
```

### **2.2. Entidades FASE 2 - Gestión Avanzada (Rediseñadas)**

#### **ReturnDiscrepancy (Mejorada según comentarios)**
```typescript
interface ReturnDiscrepancy {
  id: string;
  eventId: string;              // FK a Event
  
  type: DiscrepancyType;
  itemCode: string;
  expectedQuantity: number;
  actualQuantity: number;
  difference: number;           // Calculado: actual - expected
  percentageVariance: number;   // % de variación
  
  // MEJORA: impactLevel como enum para control
  impactLevel: ImpactLevel;
  
  // Resolución de discrepancia
  resolution?: string;
  resolvedBy?: string;          // FK a User - MEJORADO
  resolvedAt?: Date;
  
  // Estados de la discrepancia
  status: DiscrepancyStatus;
  requiresApproval: boolean;
  approvedBy?: string;          // FK a User
  approvedAt?: Date;
  
  // Información financiera (FASE 2)
  estimatedCost?: number;
  actualCost?: number;
  
  createdAt: Date;
  updatedAt: Date;
  
  // ÍNDICES para análisis
  // INDEX idx_discrepancy_impact_status (impactLevel, status)
  // INDEX idx_discrepancy_resolver (resolvedBy, resolvedAt)
}

enum ImpactLevel {
  LOW = 'LOW',                  // <5% variación
  MEDIUM = 'MEDIUM',            // 5-15% variación  
  HIGH = 'HIGH',                // 15-30% variación
  CRITICAL = 'CRITICAL'         // >30% variación
}

enum DiscrepancyStatus {
  PENDING = 'PENDING',
  IN_REVIEW = 'IN_REVIEW',
  RESOLVED = 'RESOLVED',
  ESCALATED = 'ESCALATED',
  CLOSED = 'CLOSED'
}
```

---

## 🏗️ **3. ARQUITECTURA DE BASE DE DATOS OPTIMIZADA**

### **3.1. Esquema de Índices para Performance <2 segundos**

```sql
-- ÍNDICES CRÍTICOS PARA BÚSQUEDAS RÁPIDAS

-- Events: Búsquedas por matrícula (más frecuente)
CREATE INDEX idx_events_license_plate ON events(license_plate);

-- Events: Búsquedas por empresa y fecha
CREATE INDEX idx_events_company_date ON events(company_id, event_date_time);

-- Events: Filtros por estado
CREATE INDEX idx_events_status_metadata ON events(status, has_basic_metadata);

-- Companies: RUT único para validación rápida
CREATE UNIQUE INDEX idx_companies_rut ON companies(rut);

-- Users: Email único para login
CREATE UNIQUE INDEX idx_users_email ON users(email);

-- Users: Filtros por empresa (para CLIENT_USER)
CREATE INDEX idx_users_company_active ON users(company_id, is_active) 
WHERE company_id IS NOT NULL;

-- BasicEventMetadata: Búsquedas por guía
CREATE INDEX idx_metadata_guide_number ON basic_event_metadata(guide_number)
WHERE guide_number IS NOT NULL;

-- UserPermissions: Verificación rápida de permisos
CREATE INDEX idx_user_permissions_lookup ON user_permissions(user_id, permission);

-- ÍNDICES COMPUESTOS para búsquedas complejas
CREATE INDEX idx_events_search_combined ON events(company_id, license_plate, event_date_time);
```

### **3.2. Particionamiento para Escalabilidad**

```sql
-- Particionamiento por fecha para tablas grandes
CREATE TABLE events (
  -- campos...
) PARTITION BY RANGE (YEAR(event_date_time) * 100 + MONTH(event_date_time)) (
  PARTITION p202507 VALUES LESS THAN (202508),
  PARTITION p202508 VALUES LESS THAN (202509),
  -- ... particiones mensuales
);

-- Tabla de auditoría particionada
CREATE TABLE audit_logs (
  -- campos...
) PARTITION BY RANGE (YEAR(created_at) * 100 + MONTH(created_at));
```

### **3.3. Validaciones de Negocio a Nivel de BD**

```sql
-- Validación RUT chileno
ALTER TABLE companies ADD CONSTRAINT chk_rut_format 
CHECK (rut REGEXP '^[0-9]{7,8}-[0-9Kk]$');

-- Validación matrícula chilena
ALTER TABLE events ADD CONSTRAINT chk_license_plate_format
CHECK (license_plate REGEXP '^[A-Z]{2}[0-9]{4}$|^[A-Z]{4}[0-9]{2}$');

-- Validación confianza ANPR
ALTER TABLE events ADD CONSTRAINT chk_confidence_range
CHECK (confidence >= 0 AND confidence <= 100);

-- Unicidad firstName + lastName por empresa
ALTER TABLE users ADD CONSTRAINT uk_user_name_company 
UNIQUE (first_name, last_name, company_id);

-- Jerarquía de permisos a nivel aplicación
-- VIEW_VIDEOS es prerequisito para DOWNLOAD_VIDEOS
```

---

## 🔄 **4. FLUJOS DE USUARIO REFINADOS CON MATERIAL DESIGN**

### **4.1. Interface Material Design v5 - Wireframes de Alta Fidelidad**

#### **Dashboard Principal - Operador**
```
╭─────────────────────────────────────────────────────────────────╮
│ 🏢 DOM CCTV                    🔍 [Búsqueda global]  👤 Juan P. │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 📊 RESUMEN EJECUTIVO                        📅 07/07/2025     │
│ ┌─────────────┬─────────────┬─────────────┬─────────────┐      │
│ │ 📹 EVENTOS  │ ✅ DOCUMENT │ ⏳ PENDIENTE│ 🏢 EMPRESAS │      │
│ │    23       │     18      │      5      │      8      │      │
│ └─────────────┴─────────────┴─────────────┴─────────────┘      │
│                                                                 │
│ 🔍 BÚSQUEDA INTELIGENTE                                        │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Matrícula: [ABC-123▓    ] 📅 Desde: [    ] Hasta: [    ] │ │
│ │ Empresa:   [▼ Todas     ] 🔄 Estado: [▼ Todos        ] │ │
│ │                           [🔍 Buscar] [🧹 Limpiar]    │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ 📋 EVENTOS RECIENTES                              🔄 Auto-refresh│
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🚛 ABC-123  │ 12:45 │ Constructora Los Álamos │ ✅ Doc     │ │
│ │ [▶️ Ver]    │[📝Info]│ [💾 Exportar]           │            │ │
│ ├─────────────────────────────────────────────────────────────┤ │
│ │ 🚛 XYZ-789  │ 12:30 │ Inmobiliaria Sur       │ ⏳ Pendiente│ │
│ │ [▶️ Ver]    │[📝Info]│ [💾 Exportar]           │            │ │
│ └─────────────────────────────────────────────────────────────┘ │
╰─────────────────────────────────────────────────────────────────╯
```

#### **Visualizador de Video Multi-Cámara**
```
╭─────────────────────────────────────────────────────────────────╮
│ ← Volver │ 🚛 ABC-123 - 07/07/2025 12:45 - Constructora Los Á. │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 🎥 VIDEO PRINCIPAL                    📋 METADATOS BÁSICOS     │
│ ┌─────────────────────────────┐       ┌─────────────────────────┐ │
│ │ ████████████████████████████│       │ 🏢 Empresa:            │ │
│ │ ████████████████████████████│       │ Constructora Los Álamos │ │
│ │ ████████████████████████████│       │                         │ │
│ │ ████████████████████████████│       │ 📄 Guía: GD-2025-001   │ │
│ │ ████████████████████████████│       │ 📅 Fecha: 07/07/2025   │ │
│ │ ████████████████████████████│       │ 🏗️ Proyecto:           │ │
│ │ ▶️ 00:02:15 / 00:05:30       │       │ Edificio Los Álamos    │ │
│ │ [⏮️][⏸️][⏭️] 🔊────── ⛶    │       │                         │ │
│ └─────────────────────────────┘       │ 📝 Descripción:        │ │
│                                       │ Encofrados metálicos    │ │
│ 🎯 OTRAS CÁMARAS (8)                   │ varios                  │ │
│ [📹 C1][📹 C2][📹 C3][📹 C4]          │                         │ │
│ [📹 C5][📹 C6][📹 C7][📹 C8]          │ 📝 Observaciones:       │ │
│                                       │ [Carga completa...]     │ │
│ 📸 HERRAMIENTAS                        │                         │ │
│ [📷 Capturar][🔍 Zoom 10x][⏰ Marca]    │ [💾 Guardar][✅ Listo] │ │
│                                       └─────────────────────────┘ │
╰─────────────────────────────────────────────────────────────────╯
```

#### **Portal Cliente Arrendatario (Material Design)**
```
╭─────────────────────────────────────────────────────────────────╮
│ 🏢 Constructora Los Álamos S.A.              👤 María González  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 📊 MI DASHBOARD                             📅 Julio 2025      │
│ ┌─────────────┬─────────────┬─────────────┬─────────────┐      │
│ │ 📹 MIS VIDEO│ ✅ COMPLETOS│ ⏳ PENDIENTE│ 📈 ESTE MES │      │
│ │     12      │      8      │      4      │     45      │      │
│ └─────────────┴─────────────┴─────────────┴─────────────┘      │
│                                                                 │
│ 🚨 ACCIONES REQUERIDAS                                         │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ ⚠️ 4 videos pendientes de información básica               │ │
│ │ 📅 Devolución programada para mañana requiere verificación │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ 📋 MIS VIDEOS PENDIENTES                                       │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ 🚛 ABC-123  │ Hoy 12:45    │ ⏳ Pendiente Info           │ │
│ │             │              │ [▶️ Ver][📝 Completar]       │ │
│ ├─────────────────────────────────────────────────────────────┤ │
│ │ 🚛 XYZ-789  │ Hoy 08:30    │ ❌ Sin Info                 │ │
│ │             │              │ [▶️ Ver][📝 Completar]       │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ 📊 MI HISTORIAL RECIENTE                   [📄 Ver Reporte]   │
│ Videos Este Mes: 8  |  Completados: 6  |  Tiempo Prom: 5 min │
╰─────────────────────────────────────────────────────────────────╯
```

### **4.2. Formulario de Metadatos con Validación Material Design**

```
╭─────────────────────────────────────────────────────────────────╮
│ ← Volver │ Completar Información - ABC-123 - Hoy 12:45          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ 📄 INFORMACIÓN BÁSICA DE DEVOLUCIÓN                           │
│                                                                 │
│ Número de Guía *                                               │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ GD-2025-001▓                                                │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ Fecha de Guía *                  Proyecto de Origen *          │
│ ┌─────────────────┐             ┌─────────────────────────────┐ │
│ │ 07/07/2025▓     │             │ Edificio Norte▓             │ │
│ └─────────────────┘             └─────────────────────────────┘ │
│                                                                 │
│ 📦 DESCRIPCIÓN DE LA CARGA                                    │
│                                                                 │
│ Tipo de Carga *                                                │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Encofrados Metálicos                          ▼             │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ Descripción General                                             │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Paneles y esquineros varios en buen estado▓                │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ Estado General                                                  │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Buen Estado                               ▼                 │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ 📝 OBSERVACIONES                                               │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ Carga completa según programación.▓                        │ │
│ │ Sin novedades en el transporte.                             │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ 🎥 VIDEO ASOCIADO                                              │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │ [▶️ Ver Video Llegada] [▶️ Ver Video Descarga]               │ │
│ └─────────────────────────────────────────────────────────────┘ │
│                                                                 │
│ ┌─────────────────────────────────────────────────────────────┐ │
│ │          [💾 Guardar Borrador] [✅ Completar] [❌ Cancelar]  │ │
│ └─────────────────────────────────────────────────────────────┘ │
╰─────────────────────────────────────────────────────────────────╯
```

---

## 🎯 **5. CRITERIOS DE ACEPTACIÓN REFINADOS**

### **5.1. FASE 1 - CORE ESENCIAL (6 Sprints Optimizados)**

#### **Sprint 1: Fundaciones con Arquitectura Optimizada**
- [ ] **Base de datos:** Esquema con índices optimizados implementado
- [ ] **Autenticación:** 4 roles con jerarquía de permisos funcionando
- [ ] **Integración Hikvision:** Conexión estable con cámaras ANPR
- [ ] **Detección ANPR:** Captura automática con confianza ≥85%
- [ ] **Performance:** Consultas de autenticación <500ms

#### **Sprint 2: Búsqueda Ultra-Rápida**
- [ ] **Búsqueda por matrícula:** Respuesta <2 segundos para 10,000+ eventos
- [ ] **Filtros avanzados:** Empresa, fecha, estado con auto-completado
- [ ] **Paginación:** Máximo 50 resultados por página con scroll infinito
- [ ] **Índices:** Todas las búsquedas frecuentes optimizadas
- [ ] **Cache:** Resultados cacheados para búsquedas repetitivas

#### **Sprint 3: Gestión de Metadatos con Material Design**
- [ ] **Formularios:** Validación en tiempo real con Material Design v5
- [ ] **Validación RUT:** Formato chileno validado automáticamente
- [ ] **Validación matrícula:** Formatos antiguos y nuevos soportados
- [ ] **Guardado automático:** Borrador cada 30 segundos
- [ ] **Control de acceso:** CLIENT_USER solo ve su empresa

#### **Sprint 4: Video Premium con Zoom 10x**
- [ ] **Calidad 6MP:** Reproducción sin pérdida hasta zoom 10x
- [ ] **Multi-cámara:** Grid 2x4 sincronizado para 8 cámaras
- [ ] **Performance:** Carga de video <3 segundos
- [ ] **Controles:** Navegación temporal fluida
- [ ] **Capturas:** Función de screenshot con anotaciones

#### **Sprint 5: Dashboard y Reportes Material Design**
- [ ] **Dashboard ejecutivo:** Métricas en tiempo real
- [ ] **Gráficos:** Tendencias con Material Design Charts
- [ ] **Exportación:** Excel con formato profesional
- [ ] **Filtros:** Filtrado dinámico en reportes
- [ ] **Responsive:** Interface adaptada para tablets

#### **Sprint 6: Sistema Completo y Optimizado**
- [ ] **Auditoría:** Log completo de acciones de usuario
- [ ] **Performance:** <2 segundos para todas las búsquedas
- [ ] **Escalabilidad:** Soporte para 1000+ eventos diarios
- [ ] **Documentación:** Manual de usuario completo
- [ ] **Testing:** Cobertura >80% en funciones críticas

### **5.2. Validaciones de Negocio Específicas**

#### **Validación de RUT Chileno**
```typescript
function validateChileanRUT(rut: string): boolean {
  // Formato: 12345678-9 o 12345678-K
  const rutRegex = /^(\d{7,8})-([0-9Kk])$/;
  const match = rut.match(rutRegex);
  
  if (!match) return false;
  
  const [, number, checkDigit] = match;
  const calculatedDigit = calculateRUTCheckDigit(number);
  
  return checkDigit.toLowerCase() === calculatedDigit.toLowerCase();
}
```

#### **Validación de Matrícula Chilena**
```typescript
function validateChileanLicensePlate(plate: string): boolean {
  const formats = {
    OLD_FORMAT: /^[A-Z]{2}[0-9]{4}$/,     // AA1234
    NEW_FORMAT: /^[A-Z]{4}[0-9]{2}$/      // ABCD12
  };
  
  return Object.values(formats).some(regex => regex.test(plate));
}
```

#### **Jerarquía de Permisos**
```typescript
const PERMISSION_HIERARCHY = {
  DOWNLOAD_VIDEOS: ['VIEW_VIDEOS'],
  SEARCH_ALL_COMPANIES: ['SEARCH_OWN_COMPANY'],
  MANAGE_USERS: ['VIEW_AUDIT_LOGS'],
  GENERATE_DETAILED_REPORTS: ['GENERATE_BASIC_REPORTS'],
  SYSTEM_CONFIG: ['MANAGE_USERS', 'MANAGE_COMPANIES']
};

function userHasPermission(user: User, permission: Permission): boolean {
  // Verificar permiso directo
  if (user.permissions.includes(permission)) return true;
  
  // Verificar permisos que incluyen este
  return user.permissions.some(userPerm => 
    PERMISSION_HIERARCHY[userPerm]?.includes(permission)
  );
}
```

---

## 🚀 **6. FASE 2 - GESTIÓN AVANZADA REFINADA**

### **6.1. Entidades Avanzadas con Validación de Inventario**

#### **ScaffoldingItemType (Catálogo de Encofrados)**
```typescript
interface ScaffoldingItemType {
  id: string;
  code: string;                  // Código único del tipo (ej: "PAN-60x240")
  description: string;           // "Panel metálico 60x240cm"
  category: ScaffoldingCategory; // Categoría para agrupación
  
  // Especificaciones técnicas
  dimensions: {
    width: number;               // cm
    height: number;              // cm
    depth?: number;              // cm para elementos 3D
  };
  
  weight: number;                // kg
  material: MaterialType;
  
  // Configuración de negocio
  standardRentalPeriod: number;  // días estándar de arriendo
  replacementCost: number;       // costo de reemplazo
  repairThreshold: number;       // % daño máximo antes de reemplazo
  
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  
  // ÍNDICE para búsquedas rápidas en inventario
  // INDEX idx_scaffolding_type_code (code)
  // INDEX idx_scaffolding_type_category (category, isActive)
}

enum ScaffoldingCategory {
  PANELS = 'PANELS',             // Paneles
  CORNERS = 'CORNERS',           // Esquineros
  SUPPORTS = 'SUPPORTS',         // Soportes
  ACCESSORIES = 'ACCESSORIES'    // Accesorios
}

enum MaterialType {
  STEEL = 'STEEL',               // Acero
  ALUMINUM = 'ALUMINUM',         // Aluminio
  COMPOSITE = 'COMPOSITE'        // Compuesto
}
```

#### **DetailedInventoryCount (Conteo Detallado FASE 2)**
```typescript
interface DetailedInventoryCount {
  id: string;
  eventId: string;               // FK a Event
  
  // Información del conteo
  countedBy: string;             // FK a User
  countedAt: Date;
  reviewedBy?: string;           // FK a User (supervisor)
  reviewedAt?: Date;
  
  // Status del conteo
  status: CountStatus;
  
  // Items contados
  items: ScaffoldingItemCount[];
  
  // Resumen calculado automáticamente
  summary: {
    totalItemsExpected: number;
    totalItemsFound: number;
    totalDiscrepancies: number;
    valueAtRisk: number;         // Valor monetario en riesgo
    riskLevel: RiskLevel;
  };
  
  // Observaciones del contador
  observations?: string;
  
  createdAt: Date;
  updatedAt: Date;
}

interface ScaffoldingItemCount {
  id: string;
  inventoryCountId: string;      // FK a DetailedInventoryCount
  itemTypeId: string;            // FK a ScaffoldingItemType
  
  // Cantidades
  expectedQuantity: number;      // Según contrato de arriendo
  countedQuantity: number;       // Contado físicamente
  
  // Estado de las piezas
  conditionBreakdown: {
    excellent: number;
    good: number;
    fair: number;
    poor: number;
    damaged: number;
    missing: number;
  };
  
  // Discrepancia calculada
  discrepancy: {
    quantity: number;            // diferencia en cantidad
    percentage: number;          // % de variación
    estimatedCost: number;       // costo estimado de la discrepancia
  };
  
  // Observaciones específicas del item
  itemObservations?: string;
  
  // Evidencia fotográfica
  photoEvidence: string[];       // URLs de fotos
}

enum CountStatus {
  IN_PROGRESS = 'IN_PROGRESS',
  PENDING_REVIEW = 'PENDING_REVIEW',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  REQUIRES_RECOUNT = 'REQUIRES_RECOUNT'
}

enum RiskLevel {
  MINIMAL = 'MINIMAL',           // <2% variación
  LOW = 'LOW',                   // 2-5% variación
  MODERATE = 'MODERATE',         // 5-10% variación
  HIGH = 'HIGH',                 // 10-20% variación
  CRITICAL = 'CRITICAL'          // >20% variación
}
```

### **6.2. Sistema de Integración con APIs Externas**

#### **InventoryAPI (Integración con Sistemas de Arriendo)**
```typescript
// API separada para integración con sistemas de inventario (FASE 2)
interface InventoryIntegrationAPI {
  // Sincronización de inventarios arrendados
  syncRentalInventory(companyId: string, projectId: string): Promise<RentalInventory>;
  
  // Validación de devolución contra inventario original
  validateReturn(eventId: string, countedItems: ScaffoldingItemCount[]): Promise<ValidationResult>;
  
  // Cálculo automático de penalizaciones
  calculatePenalties(discrepancies: ReturnDiscrepancy[]): Promise<PenaltyCalculation>;
  
  // Generación de reportes para sistema externo
  generateInventoryReport(companyId: string, period: DateRange): Promise<InventoryReport>;
}

interface RentalInventory {
  rentalId: string;
  companyId: string;
  projectId: string;
  startDate: Date;
  expectedReturnDate: Date;
  
  items: RentalItem[];
  
  contractTerms: {
    penaltyRate: number;         // % penalización por día de retraso
    damageThreshold: number;     // % daño tolerable
    replacementCosts: Map<string, number>; // Costos por tipo de item
  };
}

interface ValidationResult {
  isValid: boolean;
  discrepancies: CalculatedDiscrepancy[];
  totalPenalty: number;
  requiresManagerApproval: boolean;
  autoApprovalEligible: boolean;
}
```

---

## 📊 **7. MÉTRICAS DE ÉXITO Y KPIs ESPECÍFICOS**

### **7.1. Métricas Técnicas de Performance**

| Métrica | Target FASE 1 | Target FASE 2 | Medición |
|---------|---------------|---------------|-----------|
| **Búsqueda por matrícula** | <2 segundos | <1 segundo | Tiempo promedio en 95th percentile |
| **Carga de video 6MP** | <3 segundos | <2 segundos | Time to first frame |
| **Zoom 10x** | Sin lag | Sin lag | Frame rate ≥30fps durante zoom |
| **Disponibilidad** | 99.5% | 99.9% | Uptime mensual |
| **Concurrencia** | 50 usuarios | 200 usuarios | Usuarios simultáneos sin degradación |

### **7.2. Métricas de Adopción y Usabilidad**

| Métrica | Target | Medición |
|---------|--------|-----------|
| **Tiempo de entrenamiento** | <30 minutos | Por usuario nuevo |
| **Tasa de adopción** | >90% | % de usuarios activos semanalmente |
| **Satisfacción** | >4.5/5 | Encuesta mensual NPS |
| **Errores de usuario** | <2% | % de formularios con errores |
| **Documentación completa** | >85% | % eventos con metadatos básicos |

### **7.3. Métricas de Negocio**

| Métrica | Valor Actual | Target | ROI |
|---------|--------------|--------|-----|
| **Tiempo búsqueda** | 15 minutos | <30 segundos | 30x reducción |
| **Disputas sin evidencia** | 40% | <5% | 8x reducción |
| **Costo operativo** | $X/mes | 60% del actual | 40% ahorro |
| **Satisfacción cliente** | Desconocido | >4/5 | Medible |

---

## 🛡️ **8. CONSIDERACIONES DE SEGURIDAD Y COMPLIANCE**

### **8.1. Protección de Datos**

```typescript
// Encriptación de datos sensibles
interface EncryptedField {
  value: string;                 // Valor encriptado
  algorithm: 'AES-256-GCM';      // Algoritmo de encriptación
  keyVersion: number;            // Versión de la clave para rotación
}

// Campos que requieren encriptación
interface SecureCompany extends Company {
  rut: EncryptedField;           // RUT encriptado en BD
  email: EncryptedField;         // Email encriptado
  phone: EncryptedField;         // Teléfono encriptado
}
```

### **8.2. Auditoría Completa**

```typescript
interface AuditLog {
  id: string;
  userId: string;                // FK a User
  action: AuditAction;
  resourceType: ResourceType;
  resourceId: string;
  
  // Contexto de la acción
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
  
  // Datos de la acción
  beforeState?: object;          // Estado anterior (para updates)
  afterState?: object;           // Estado posterior
  
  // Metadata adicional
  companyId?: string;            // Para filtrar por empresa
  sessionId: string;             // Para rastrear sesiones
  
  // Índice particionado por mes
  // PARTITION BY RANGE (YEAR(timestamp) * 100 + MONTH(timestamp))
}

enum AuditAction {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  VIEW_EVENT = 'VIEW_EVENT',
  UPDATE_METADATA = 'UPDATE_METADATA',
  DOWNLOAD_VIDEO = 'DOWNLOAD_VIDEO',
  SEARCH_EVENTS = 'SEARCH_EVENTS',
  EXPORT_DATA = 'EXPORT_DATA',
  CREATE_USER = 'CREATE_USER',
  MODIFY_PERMISSIONS = 'MODIFY_PERMISSIONS'
}

enum ResourceType {
  USER = 'USER',
  COMPANY = 'COMPANY', 
  EVENT = 'EVENT',
  VIDEO = 'VIDEO',
  REPORT = 'REPORT'
}
```

### **8.3. Control de Acceso Granular**

```typescript
// Middleware de autorización contextual
async function authorizeAction(
  user: User, 
  action: AuditAction, 
  resource: any
): Promise<boolean> {
  
  // Verificar permisos básicos
  if (!userHasPermission(user, getRequiredPermission(action))) {
    return false;
  }
  
  // Control de acceso por empresa para CLIENT_USER
  if (user.role === UserRole.CLIENT_USER) {
    if (resource.companyId && resource.companyId !== user.companyId) {
      return false;
    }
  }
  
  // Verificaciones adicionales basadas en el recurso
  return await performResourceSpecificChecks(user, action, resource);
}
```

---

## 🎯 **9. CRITERIOS DE TRANSICIÓN FASE 1 → FASE 2**

### **9.1. Métricas de Éxito FASE 1 (Requisitos para FASE 2)**

| Criterio | Métrica | Target | Status |
|----------|---------|--------|--------|
| **Adopción Masiva** | % usuarios activos diarios | >90% | ⏳ Pendiente |
| **Performance** | Búsquedas <2 segundos | 100% | ⏳ Pendiente |
| **Satisfacción** | NPS Score | >4.5/5 | ⏳ Pendiente |
| **Cobertura** | Eventos documentados | >95% | ⏳ Pendiente |
| **ROI Demostrado** | Ahorro vs inversión | >200% | ⏳ Pendiente |

### **9.2. Señales de Demanda para FASE 2**

- [ ] **Solicitudes activas:** >5 empresas solicitan conteo detallado
- [ ] **Casos de uso:** Identificación de 3+ casos donde FASE 1 es insuficiente
- [ ] **Justificación económica:** ROI proyectado >300% para features FASE 2
- [ ] **Recursos técnicos:** Equipo disponible para 6 sprints adicionales
- [ ] **Feedback cualitativo:** Usuarios expresan necesidad de features avanzadas

---

## 📅 **10. ROADMAP DE IMPLEMENTACIÓN REFINADO**

### **Trimestre 1: FASE 1 - Fundación Sólida (18 semanas)**

**Mes 1-2: Sprints 1-4 (Sistema Básico)**
- Semanas 1-3: Sprint 1 (Fundaciones + BD optimizada)
- Semanas 4-6: Sprint 2 (Búsqueda ultra-rápida)
- Semanas 7-9: Sprint 3 (Metadatos Material Design)
- Semanas 10-12: Sprint 4 (Video premium con zoom)

**Mes 3: Sprints 5-6 (Refinamiento)**
- Semanas 13-15: Sprint 5 (Dashboard y reportes)
- Semanas 16-18: Sprint 6 (Sistema completo + testing)

**Entregables Mes 3:**
- [ ] Sistema 100% operativo para documentación y búsqueda
- [ ] Performance <2 segundos garantizado
- [ ] Interface Material Design v5 completa
- [ ] 3+ usuarios entrenados por rol
- [ ] Documentación técnica y de usuario

### **Trimestre 2: Optimización y Validación (12 semanas)**

**Mes 4: Performance Tuning**
- Optimización para alta concurrencia (50+ usuarios)
- Mejoras de UI basadas en feedback inicial
- Integración básica con sistemas DOM existentes

**Mes 5-6: Validación y Mejoras**
- Periodo de prueba intensiva con datos reales
- Iteraciones basadas en feedback de usuarios
- Preparación de métricas para evaluación FASE 2

### **Trimestre 3+: FASE 2 Condicional (24+ semanas)**

**Criterio de Go/No-Go FASE 2:** Evaluación basada en métricas FASE 1

**Si FASE 2 es aprobada:**
- Mes 7-9: Sprints 7-9 (Conteo detallado + discrepancias)
- Mes 10-12: Sprints 10-12 (Analytics avanzados + integraciones)

---

## ✅ **11. CHECKLIST DE IMPLEMENTACIÓN CONTEXT ENGINEERING**

### **Pre-Desarrollo (Completado)**
- [x] **Context Engineering:** Metodología aplicada al PRD
- [x] **Comentarios integrados:** Todas las mejoras solicitadas incorporadas
- [x] **Material Design:** Especificación UI/UX definida
- [x] **Base de datos:** Esquema optimizado con índices
- [x] **Arquitectura:** Approach bifásico validado

### **Desarrollo FASE 1 (Pendiente)**
- [ ] **Ambiente desarrollo:** Docker + variables de entorno
- [ ] **CI/CD:** Pipeline automatizado con testing
- [ ] **Base datos:** MySQL 8.0 con particionamiento
- [ ] **Backend:** Node.js + TypeScript + Prisma
- [ ] **Frontend:** React + TypeScript + Material UI v5
- [ ] **Testing:** Cobertura >80% en funciones críticas

### **Validación Pre-Launch (Pendiente)**
- [ ] **Performance:** Todas las métricas <2 segundos validadas
- [ ] **Seguridad:** Penetration testing completado
- [ ] **Usabilidad:** Testing con usuarios reales (5+ por rol)
- [ ] **Integración:** APIs Hikvision funcionando 100%
- [ ] **Documentación:** Manuales técnicos y de usuario completos

### **Go-Live FASE 1 (Pendiente)**
- [ ] **Producción:** Sistema desplegado 24/7
- [ ] **Monitoreo:** Dashboards de métricas en tiempo real
- [ ] **Soporte:** Equipo técnico disponible primera semana
- [ ] **Capacitación:** 100% usuarios entrenados
- [ ] **Backup:** Procedimientos de respaldo automático

---

## 🎯 **12. CASOS DE PRUEBA ESPECÍFICOS REFINADOS**

### **Funcionalidad: Búsqueda Ultra-Rápida**

```gherkin
Escenario: Búsqueda por matrícula con performance <2 segundos
  Dado que tengo 10,000+ eventos en la base de datos
  Y soy un operador autenticado
  Cuando busco la matrícula "ABC-123"
  Entonces debo ver los resultados en menos de 2 segundos
  Y los resultados deben estar ordenados por fecha descendente
  Y debo ver máximo 50 resultados por página
  Y cada resultado debe mostrar: matrícula, fecha/hora, empresa, estado
  Y debo poder hacer clic para ver el video inmediatamente
```

### **Funcionalidad: Control de Acceso por Empresa**

```gherkin
Escenario: CLIENT_USER solo ve eventos de su empresa
  Dado que soy un CLIENT_USER de "Constructora Los Álamos" 
  Y existen eventos de múltiples empresas en el sistema
  Cuando accedo al dashboard
  Entonces debo ver solo eventos donde companyId = mi empresa
  Y NO debo ver eventos de otras empresas
  Y si intento acceder directamente a URL de otro evento
  Entonces debo recibir error 403 Forbidden
  Y la búsqueda debe filtrar automáticamente por mi empresa
```

### **Funcionalidad: Video Premium con Zoom 10x**

```gherkin
Escenario: Reproducción multi-cámara con zoom detallado
  Dado que estoy viendo un evento con 8 videos de 6MP
  Cuando selecciono "Ver todas las cámaras"
  Entonces debo ver un grid Material Design 2x4
  Y cada video debe cargar en menos de 3 segundos
  Y cuando hago zoom 10x en cualquier video
  Entonces la calidad debe mantenerse sin pixelación
  Y la navegación temporal debe permanecer sincronizada
  Y debo poder capturar screenshots con anotaciones
```

### **Funcionalidad: Validación de Formularios**

```gherkin
Escenario: Validación de RUT chileno en tiempo real
  Dado que estoy creando una nueva empresa
  Cuando ingreso RUT "12345678-9"
  Entonces el sistema debe validar el dígito verificador
  Y si es inválido, mostrar error en tiempo real
  Y cuando ingreso RUT válido "96543210-K"
  Entonces debe aceptarlo y continuar
  Y el RUT debe formatearse automáticamente
```

---

## 📈 **13. MÉTRICAS DE MONITOREO EN TIEMPO REAL**

### **Dashboard de Métricas Técnicas**

```typescript
interface SystemMetrics {
  performance: {
    avgSearchTime: number;        // ms promedio búsquedas
    avgVideoLoadTime: number;     // ms promedio carga video
    databaseResponseTime: number; // ms promedio queries BD
    apiResponseTime: number;      // ms promedio APIs Hikvision
  };
  
  usage: {
    activeUsers: number;          // usuarios concurrentes
    dailySearches: number;        // búsquedas por día
    videosWatched: number;        // videos reproducidos
    metadataCompleted: number;    // formularios completados
  };
  
  business: {
    eventsDetected: number;       // eventos ANPR detectados
    eventsDocumented: number;     // eventos con metadatos
    documentationRate: number;    // % eventos documentados
    avgDocumentationTime: number; // minutos promedio
  };
  
  errors: {
    anprFailures: number;         // fallos reconocimiento
    videoStreamErrors: number;    // errores reproducción
    authenticationErrors: number; // errores login
    systemErrors: number;        // errores generales
  };
}
```

### **Alertas Automáticas**

```typescript
interface AlertRules {
  performance: {
    searchTimeThreshold: 2000;    // ms - alerta si >2 segundos
    videoLoadThreshold: 3000;     // ms - alerta si >3 segundos
    errorRateThreshold: 0.05;     // alerta si >5% error rate
  };
  
  business: {
    anprConfidenceThreshold: 0.85; // alerta si <85% confianza
    documentationRateThreshold: 0.8; // alerta si <80% documentado
    undocumentedEventAge: 24;     // horas - alerta eventos sin documentar
  };
}
```

---

