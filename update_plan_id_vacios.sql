-- Actualiza a plan_id = 2 los clientes que no tienen plan asignado.
-- Respaldar users.db antes de ejecutar este script en producción.

BEGIN TRANSACTION;

UPDATE clientes
SET plan_id = 2
WHERE plan_id IS NULL OR plan_id = '';

COMMIT;

-- Verificacion post-ejecucion
SELECT COUNT(*) AS clientes_sin_plan
FROM clientes
WHERE plan_id IS NULL OR plan_id = '';

SELECT COUNT(*) AS clientes_con_plan_2
FROM clientes
WHERE plan_id = 2;
