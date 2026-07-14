-- Actualiza a "PINO SUAREZ" los clientes que no tienen localidad asignada.
-- Respaldar users.db antes de ejecutar este script en produccion.

BEGIN TRANSACTION;

UPDATE clientes
SET localidad = 'PINO SUAREZ'
WHERE TRIM(localidad) = '';

COMMIT;

-- Verificacion post-ejecucion
SELECT COUNT(*) AS clientes_sin_localidad
FROM clientes
WHERE TRIM(localidad) = '';

SELECT COUNT(*) AS clientes_con_pino_suarez
FROM clientes
WHERE localidad = 'PINO SUAREZ';
