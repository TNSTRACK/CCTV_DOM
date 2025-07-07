Antecedentes
Conforme a lo que hemos discutido en las reuniones internas, el objetivo principal es documentar en video las llegadas de los camiones, así como sus descargas y de segunda derivada y posterior a lo primero, el conteo del equipamiento de retorno vía análisis de los videos. 
1. Introducción
Tenemos como objetivo implementar un sistema de videovigilancia basado en tecnología Hikvision que permita documentar con precisión las tres etapas del proceso de descarga de camiones, a partir de su llegada leyendo su matricula vía APNR: 
•	Estacionamiento: Detección de la  llegada y ubicación del camión en el lugar que tenemos previsto para eso donde están las cámaras (con visión longitudinal, y perpendicular por ambos lados). 
•	Traslado de Carga al Piso: Captura en video del proceso de descarga y movimiento de la carga. 
•	Conteo/Pesaje de Mercancía: Documentación visual para validar el conteo manual y el pesaje de la carga proveniente del camión. 
La solución debe indexar cada grabación mediante metadatos (matrícula del camión, fecha y hora, como datos automáticos, y permitir posteriormente agregar datos, proveniente ya sea desde el cliente (apilamiento) o vía la misma aplicación web, de datos adicionales como datos de la empresa que envía la carga, datos dela guía de despacho del camión entre otros) y exponerlos a través de una API integrada en la plataforma de software a desarrollar . Además, se deberá garantizar alta claridad visual –permitiendo hacer zoom en los detalles críticos– y una gestión eficiente del almacenamiento, combinando opciones locales y en la nube. 
 
2. Especificaciones Técnicas del Sistema CCTV Propuesto
a) Equipos y Cámaras
•	Cantidad y Modelos: 
o	10 cámaras totales: 
 -	8 unidades del modelo DS-2CD3666G2T-IZSY (cámaras documentales) 
- 	2 unidades del modelo iDS-2CD7A46G0/P-IZHS (cámaras ANPR para reconocimiento de matrículas) 

b) Resolución y Calidad de Imagen
•	Resolución en 6 mp.  
c) Frame Rate y Rendimiento
•	Frame Rate Sugerido: 15 FPS. 
d) Almacenamiento y Gestión de Datos
•	Configuración Base: 
o	Sistema NVR que, según la propuesta original, contempla 120 días de grabación disponible en local.
•	Cálculos Aproximados (para 10 cámaras, grabación de 12 horas diarias): 
o	Consumo diario estimado: 300 GB
o	120 días: ≈ 34 TB
•	Estrategia de Almacenamiento Híbrido: 
o	Nivel Activo (Acceso Inmediato): Almacenamiento local de alta velocidad para los primeros 120 días.
o	Nivel de Archivo (Acceso Diferido- OPCIONAL): Migración automática a soluciones de “almacenamiento en frío”, ya sea mediante discos de alta capacidad de bajo rendimiento o mediante integración con servicios en la nube :
recomendado: https://aws.amazon.com/s3/storage-classes/glacier/?nc2=h_ql_prod_st_s3g).

•	Impacto en Ancho de Banda: 
o	Se estima que cada cámara consume aproximadamente 5,6 Mbps, resultando en un consumo total de ~56 Mbps para 10 cámaras, con un margen adicional para garantizar la estabilidad de la red. Esta red es separada de la red del cliente, solo se usa la red del cliente para cuando se consultan videos.
 
3. Propuesta de Indexación e Integración vía API
Para facilitar la recuperación de grabaciones mediante la plataforma TNS TRACK, se propone la siguiente estrategia de indexación y API:
a)	Metadatos y Esquema de Indexación
o	Campos Principales: 
- Matrícula del camión: Identificador único para cada vehículo. 
- Fecha: Formato YYYY-MM-DD. 
- Hora: Registro de la hora exacta (HH:MM:SS) del evento. 
•	Campos Adicionales (opcionales): 
o	Tipo de proceso: Estacionamiento, traslado o conteo/pesaje.
o	ID de cámara: Para identificar la fuente de la grabación.
o	Guía de Despacho u Orden de Trabajo (desde sistemas cliente)
o	Número de Cliente y Nombre de Cliente (desde sistemas cliente )
b)	Integración mediante OpenAPI
o	Plataforma: HikCentral Professional, que soporta integración vía OpenAPI .
o	Funcionamiento: 
- El sistema indexa automáticamente cada evento grabado con los metadatos mencionados. 
- El software podrá consultar la API RESTful utilizando la matrícula y el rango de fecha/hora para obtener la URL de reproducción o la grabación específica (video) o incluso, tener una foto del primer fotograma o tal vez los 10 primeros segundos e video para una previsión . 

c)	Esquema de Flujo
1.	Captura de video en las cámaras instaladas en cada etapa.
2.	Almacenamiento en el NVR con indexación automática de metadatos.
3.	Consulta vía API: 
- el software consolida la información proveniente de los sistemas del cliente con los datos de captura de las cámaras envía la consulta (por matrícula y fecha/hora). 
- El sistema responde con la ubicación o URL del video solicitado. 
4.	Visualización: El usuario puede reproducir el video y, de ser necesario, hacer zoom en áreas específicas para validar el conteo manual.
 

c)	Recomendación de Solución Híbrida
o	Estrategia: 
- 120 días de acceso inmediato: Se almacenan en un NVR local de alto rendimiento. 
- 1+20 días de archivo en diferido: Se migran a una solución de almacenamiento en “frío” (en la nube) para optimizar costos y mantener la integridad de los datos. 
o	Esta estrategia garantiza rapidez en el acceso a los datos recientes y una solución económica para el archivo a largo plazo.
