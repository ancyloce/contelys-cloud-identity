-- name: ReadPrincipals :exec
-- Admission reads principals on every request, so readiness reads them too: it fails until the
-- migrations have created the table and while the database cannot be read.
SELECT 1 FROM principal LIMIT 1;
