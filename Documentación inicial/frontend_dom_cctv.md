# Frontend Documentation - DOM CCTV
## Arquitectura y Especificaciones Técnicas

### 1. Stack Tecnológico

#### Framework Principal
- **React 18+** con TypeScript
- **Vite** como bundler para desarrollo rápido
- **React Router v6** para navegación

#### Librerías de UI y Estilos
- **Material-UI (MUI) v5** como sistema de diseño principal
- **Emotion** (incluido con MUI) para estilos dinámicos
- **CSS Modules** para estilos específicos de componentes
- **MUI Icons** para iconografía consistente

#### Gestión de Estado
- **TanStack Query (React Query) v4** para estado del servidor y cache
- **Zustand** para estado global de la aplicación
- **React Hook Form** para gestión de formularios

#### Librerías Especializadas
- **Video.js** o **React Player** para reproducción de video RTSP
- **Date-fns** para manipulación de fechas
- **Axios** para llamadas HTTP
- **React-Zoom-Pan-Pinch** para funcionalidades de zoom en video

### 2. Arquitectura de Componentes

#### Estructura de Directorios
```
src/
├── components/           # Componentes reutilizables
│   ├── common/          # Componentes genéricos
│   ├── video/           # Componentes de video
│   ├── forms/           # Formularios especializados
│   └── layout/          # Componentes de layout
├── pages/               # Páginas principales
├── hooks/               # Custom hooks
├── services/            # Servicios y APIs
├── stores/              # Stores de Zustand
├── types/               # Definiciones TypeScript
├── utils/               # Utilidades
└── assets/              # Recursos estáticos
```

#### Componentes Principales

**Layout Components:**
- `AppLayout` - Layout principal con navegación
- `Sidebar` - Barra lateral de navegación
- `TopBar` - Barra superior con búsqueda rápida
- `ProtectedRoute` - Wrapper para rutas protegidas

**Video Components:**
- `VideoPlayer` - Reproductor principal con controles avanzados
- `VideoTimeline` - Línea de tiempo interactiva
- `VideoZoom` - Controles de zoom y pan
- `ThumbnailPreview` - Previsualizaciones de video

**Search Components:**
- `SearchBar` - Búsqueda avanzada con filtros
- `FilterPanel` - Panel de filtros laterales
- `SearchResults` - Lista de resultados
- `QuickSearch` - Búsqueda rápida por matrícula

**Data Components:**
- `EventDataTable` - Tabla de eventos con paginación
- `MetadataForm` - Formulario para agregar metadatos
- `ReportGenerator` - Generador de reportes
- `Dashboard` - Panel de control principal

### 3. Navegación y Routing

#### Estructura de Navegación

**Barra Superior (Principal):**
- Dashboard
- Búsqueda de Eventos
- Reportes

**Barra Lateral (Secundaria):**
- Configuración
- Gestión de Usuarios
- Lista de Clientes
- Auditoría
- Ayuda

#### Rutas Principales

```typescript
// Rutas públicas
/login
/forgot-password

// Rutas protegidas por rol
/ (Dashboard)
/search (Búsqueda de eventos)
/events/:id (Detalle de evento)
/reports (Reportes)
/admin/users (Gestión usuarios - solo Admin)
/admin/settings (Configuración - solo Admin)
/client/metadata (Metadatos cliente - solo Cliente)
/profile (Perfil de usuario)
```

### 4. Gestión de Estado

#### TanStack Query (Estado del Servidor)

**Configuración del Query Client:**
```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutos
      cacheTime: 10 * 60 * 1000, // 10 minutos
      retry: 3,
      refetchOnWindowFocus: false,
    },
  },
});
```

**Queries Principales:**
- `useEvents` - Lista de eventos con filtros
- `useEvent` - Evento específico con metadatos
- `useVideoUrl` - URL de video para reproducción
- `useUsers` - Gestión de usuarios (admin)
- `useReports` - Datos para reportes
- `useClients` - Lista de clientes

**Mutations Principales:**
- `useAddMetadata` - Agregar metadatos a evento
- `useUpdateEvent` - Actualizar información de evento
- `useCreateUser` - Crear nuevo usuario
- `useGenerateReport` - Generar reporte

#### Zustand (Estado Global)

**Auth Store:**
```typescript
interface AuthState {
  user: User | null;
  token: string | null;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
  hasPermission: (permission: string) => boolean;
}
```

**UI Store:**
```typescript
interface UIState {
  sidebarOpen: boolean;
  theme: 'light' | 'dark';
  currentFilters: SearchFilters;
  selectedEvent: string | null;
  toggleSidebar: () => void;
  setFilters: (filters: SearchFilters) => void;
}
```

**Video Store:**
```typescript
interface VideoState {
  currentVideo: string | null;
  playbackTime: number;
  isPlaying: boolean;
  volume: number;
  zoomLevel: number;
  setCurrentVideo: (url: string) => void;
  updatePlaybackTime: (time: number) => void;
}
```

### 5. Componentes de Video

#### VideoPlayer Component

**Props Interface:**
```typescript
interface VideoPlayerProps {
  src: string;
  poster?: string;
  metadata: EventMetadata;
  onTimeUpdate?: (time: number) => void;
  onMarkerAdd?: (time: number, note: string) => void;
  controls?: boolean;
  autoplay?: boolean;
}
```

**Funcionalidades:**
- Reproducción de streams RTSP via proxy
- Controles personalizados con MUI
- Zoom y pan en video con alta resolución (6MP)
- Marcadores temporales
- Capturas de pantalla
- Navegación frame-by-frame
- Sincronización con metadatos

#### VideoTimeline Component

**Funcionalidades:**
- Visualización de eventos en línea de tiempo
- Navegación rápida por timestamps
- Indicadores de actividad por cámara
- Zoom temporal para análisis detallado

### 6. Formularios y Validación

#### React Hook Form Setup

**Configuración Base:**
```typescript
const metadataForm = useForm<MetadataFormData>({
  resolver: zodResolver(metadataSchema),
  defaultValues: {
    rutEmpresa: '',
    numeroGuiaDespacho: '',
    fechaGuiaDespacho: null,
    descripcionCarga: '',
    ordenTrabajo1: '',
    ordenTrabajo2: '',
    recepcionistaId: '',
  },
});
```

**Esquemas de Validación (Zod):**
```typescript
const metadataSchema = z.object({
  rutEmpresa: z.string().min(1, 'RUT de empresa requerido'),
  numeroGuiaDespacho: z.string().min(1, 'Número de guía requerido'),
  fechaGuiaDespacho: z.date({ required_error: 'Fecha requerida' }),
  descripcionCarga: z.string().min(1, 'Descripción requerida'),
  ordenTrabajo1: z.string().min(1, 'Orden de trabajo requerida'),
  ordenTrabajo2: z.string().optional(),
  recepcionistaId: z.string().min(1, 'Recepcionista requerido'),
});
```

### 7. Integración con APIs

#### Axios Configuration

**Base Configuration:**
```typescript
const apiClient = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor para JWT
apiClient.interceptors.request.use((config) => {
  const token = authStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});
```

**Service Functions:**
```typescript
// Búsqueda de eventos
export const searchEvents = (filters: SearchFilters): Promise<Event[]> => {
  return apiClient.get('/api/events', { params: filters });
};

// Obtener URL de video
export const getVideoUrl = (eventId: string): Promise<{ url: string }> => {
  return apiClient.get(`/api/events/${eventId}/video`);
};

// Agregar metadatos
export const addMetadata = (eventId: string, metadata: Metadata): Promise<void> => {
  return apiClient.post(`/api/events/${eventId}/metadata`, metadata);
};
```

### 8. Optimización de Rendimiento

#### Code Splitting
- Lazy loading de páginas no críticas
- Componentes de video cargados dinámicamente
- Chunks separados para bibliotecas pesadas

#### Video Optimization
- Preload de thumbnails para navegación rápida
- Buffer inteligente basado en velocidad de conexión
- Calidad adaptativa según dispositivo

#### Data Fetching
- Infinite queries para listas grandes
- Prefetch de datos relacionados
- Cache estratégico con invalidación inteligente

### 9. Responsive Design

#### Breakpoints MUI
```typescript
const theme = createTheme({
  breakpoints: {
    values: {
      xs: 0,
      sm: 600,
      md: 900,
      lg: 1200,
      xl: 1536,
    },
  },
});
```

#### Adaptaciones por Dispositivo
- **Desktop (>1200px):** Layout completo con sidebar
- **Tablet (600-1200px):** Sidebar colapsable, grid adaptativo
- **Mobile (<600px):** Navegación drawer, vistas simplificadas

### 10. Tematización y Estilos

#### Tema Personalizado MUI
```typescript
const theme = createTheme({
  palette: {
    primary: {
      main: '#1976d2', // Azul corporativo
      light: '#42a5f5',
      dark: '#1565c0',
    },
    secondary: {
      main: '#dc004e', // Rojo Hikvision
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    h1: {
      fontSize: '2.5rem',
      fontWeight: 600,
    },
    body1: {
      fontSize: '0.875rem',
    },
  },
  shape: {
    borderRadius: 8,
  },
});
```

### 11. Testing Strategy

#### Unit Testing
- **Vitest** para tests unitarios
- **React Testing Library** para componentes
- Coverage mínimo del 80% en componentes críticos

#### Integration Testing
- Tests de flujos de usuario completos
- Mocking de APIs con MSW
- Tests de navegación entre páginas

#### E2E Testing
- **Playwright** para tests end-to-end
- Scenarios críticos: login, búsqueda, reproducción video
- Tests de regresión automatizados

### 12. Build y Deployment

#### Configuración de Build
```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  build: {
    target: 'es2015',
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          mui: ['@mui/material', '@mui/icons-material'],
          video: ['video.js', 'react-player'],
        },
      },
    },
  },
});
```

#### Environment Variables
```env
REACT_APP_API_URL=http://localhost:3001/api
REACT_APP_VIDEO_PROXY_URL=http://localhost:3001/video-proxy
REACT_APP_VERSION=1.0.0
REACT_APP_ENVIRONMENT=production
```

---

**Documento técnico validado para desarrollo frontend React con integración Hikvision**