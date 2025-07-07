-- examples/database/queries.sql
-- Patrones estándar para consultas optimizadas DOM CCTV

-- PATRÓN: Búsqueda de eventos con filtros dinámicos y paginación
-- Usar esta estructura para todas las búsquedas principales
SELECT 
    e.id,
    e.license_plate,
    e.event_date,
    e.camera_id,
    e.camera_name,
    e.video_path,
    e.thumbnail_path,
    e.processed,
    e.confidence_level,
    e.created_at,
    
    -- Metadatos asociados
    m.id as metadata_id,
    m.guide_number,
    m.guide_date,
    m.cargo_description,
    m.work_order_1,
    m.work_order_2,
    
    -- Información de empresa
    c.id as company_id,
    c.rut as company_rut,
    c.name as company_name,
    
    -- Recepcionista
    u.first_name as receptionist_first_name,
    u.last_name as receptionist_last_name
    
FROM events e
LEFT JOIN metadata_entries m ON e.id = m.event_id
LEFT JOIN companies c ON m.company_id = c.id
LEFT JOIN users u ON m.receptionist_id = u.id
WHERE 1=1
    -- Filtros dinámicos (agregar según necesidad)
    AND (@license_plate IS NULL OR e.license_plate LIKE CONCAT('%', @license_plate, '%'))
    AND (@start_date IS NULL OR e.event_date >= @start_date)
    AND (@end_date IS NULL OR e.event_date <= @end_date)
    AND (@camera_id IS NULL OR e.camera_id = @camera_id)
    AND (@company_id IS NULL OR m.company_id = @company_id)
ORDER BY e.event_date DESC
LIMIT @limit OFFSET @offset;

-- PATRÓN: Consulta de estadísticas para dashboard
-- Usar agregaciones eficientes con subqueries
SELECT 
    DATE(e.event_date) as date,
    COUNT(*) as total_events,
    COUNT(m.id) as events_with_metadata,
    COUNT(DISTINCT e.license_plate) as unique_vehicles,
    COUNT(DISTINCT m.company_id) as active_companies,
    ROUND(AVG(e.confidence_level), 2) as avg_confidence,
    ROUND((COUNT(m.id) * 100.0) / COUNT(*), 2) as completion_percentage
FROM events e
LEFT JOIN metadata_entries m ON e.id = m.event_id
WHERE e.event_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
GROUP BY DATE(e.event_date)
ORDER BY date DESC;

-- PATRÓN: Búsqueda full-text optimizada
-- Para buscar por múltiples campos de texto
SELECT 
    e.*,
    MATCH(e.license_plate) AGAINST(@search_term IN BOOLEAN MODE) +
    MATCH(m.guide_number, m.cargo_description) AGAINST(@search_term IN BOOLEAN MODE) +
    MATCH(c.name) AGAINST(@search_term IN BOOLEAN MODE) as relevance_score
FROM events e
LEFT JOIN metadata_entries m ON e.id = m.event_id
LEFT JOIN companies c ON m.company_id = c.id
WHERE MATCH(e.license_plate) AGAINST(@search_term IN BOOLEAN MODE)
   OR MATCH(m.guide_number, m.cargo_description) AGAINST(@search_term IN BOOLEAN MODE)
   OR MATCH(c.name) AGAINST(@search_term IN BOOLEAN MODE)
ORDER BY relevance_score DESC, e.event_date DESC;

-- PATRÓN: Query para reportes con agregaciones
-- Estructura para reportes de gestión
SELECT 
    c.name as company_name,
    c.rut as company_rut,
    DATE_FORMAT(e.event_date, '%Y-%m') as month,
    COUNT(*) as total_deliveries,
    COUNT(DISTINCT e.license_plate) as unique_vehicles,
    COUNT(DISTINCT m.work_order_1) as unique_work_orders,
    AVG(e.confidence_level) as avg_anpr_confidence,
    SUM(CASE WHEN m.id IS NOT NULL THEN 1 ELSE 0 END) as completed_metadata,
    ROUND((SUM(CASE WHEN m.id IS NOT NULL THEN 1 ELSE 0 END) * 100.0) / COUNT(*), 2) as completion_rate
FROM events e
LEFT JOIN metadata_entries m ON e.id = m.event_id
LEFT JOIN companies c ON m.company_id = c.id
WHERE e.event_date >= @start_date 
  AND e.event_date <= @end_date
  AND (@company_id IS NULL OR c.id = @company_id)
GROUP BY c.id, c.name, c.rut, DATE_FORMAT(e.event_date, '%Y-%m')
ORDER BY month DESC, total_deliveries DESC;

-- PATRÓN: Consulta de auditoría con filtros de seguridad
-- Para tracking de acciones de usuarios
SELECT 
    al.id,
    al.action,
    al.entity_type,
    al.entity_id,
    al.created_at,
    al.ip_address,
    u.first_name,
    u.last_name,
    u.email,
    u.role,
    c.name as company_name
FROM audit_logs al
JOIN users u ON al.user_id = u.id
LEFT JOIN companies c ON u.company_id = c.id
WHERE 1=1
  AND (@user_id IS NULL OR al.user_id = @user_id)
  AND (@action IS NULL OR al.action = @action)
  AND (@start_date IS NULL OR al.created_at >= @start_date)
  AND (@end_date IS NULL OR al.created_at <= @end_date)
  AND (@entity_type IS NULL OR al.entity_type = @entity_type)
  -- Filtro de seguridad para usuarios CLIENT_USER
  AND (@current_user_role != 'CLIENT_USER' OR u.company_id = @current_user_company_id)
ORDER BY al.created_at DESC
LIMIT @limit OFFSET @offset;

-- PATRÓN: Procedimiento almacenado para operaciones complejas
DELIMITER //
CREATE PROCEDURE GetEventsSummary(
    IN p_start_date DATE,
    IN p_end_date DATE,
    IN p_company_id VARCHAR(30)
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;
    
    -- Crear tabla temporal para resultados
    CREATE TEMPORARY TABLE temp_summary (
        license_plate VARCHAR(20),
        first_seen DATETIME,
        last_seen DATETIME,
        total_events INT,
        cameras_count INT,
        metadata_complete BOOLEAN,
        company_name VARCHAR(255)
    );
    
    -- Poblar tabla temporal
    INSERT INTO temp_summary
    SELECT 
        e.license_plate,
        MIN(e.event_date) as first_seen,
        MAX(e.event_date) as last_seen,
        COUNT(*) as total_events,
        COUNT(DISTINCT e.camera_id) as cameras_count,
        (COUNT(m.id) = COUNT(*)) as metadata_complete,
        c.name as company_name
    FROM events e
    LEFT JOIN metadata_entries m ON e.id = m.event_id
    LEFT JOIN companies c ON m.company_id = c.id
    WHERE e.event_date BETWEEN p_start_date AND p_end_date
      AND (p_company_id IS NULL OR m.company_id = p_company_id)
    GROUP BY e.license_plate, c.name;
    
    -- Retornar resultados
    SELECT * FROM temp_summary ORDER BY last_seen DESC;
    
    -- Limpiar tabla temporal
    DROP TEMPORARY TABLE temp_summary;
    
    COMMIT;
END //
DELIMITER ;