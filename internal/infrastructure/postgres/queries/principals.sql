-- name: FindPrincipalBySubject :one
SELECT p.id, p.state, p.authority_version, p.revision, p.name, p.address, p.limit_key
FROM subject_link l
JOIN principal p ON p.id = l.principal_id
WHERE l.issuer = @issuer AND l.subject = @subject;

-- name: InsertPrincipal :exec
INSERT INTO principal (id, state, authority_version, revision, name, address, limit_key)
VALUES (@id, @state, @authority_version, @revision, @name, @address, @limit_key);

-- name: InsertSubjectLink :execrows
-- A link that exists already is left alone, so that the second of two sign-ins of one subject finds
-- the first one's principal.
INSERT INTO subject_link (issuer, subject, principal_id)
VALUES (@issuer, @subject, @principal_id)
ON CONFLICT (issuer, subject) DO NOTHING;

-- name: RefreshPrincipal :one
-- The name and the address are copies of Keycloak's, refreshed at each sign-in (design section 08).
UPDATE principal SET name = @name, address = @address
WHERE id = @id
RETURNING id, state, authority_version, revision, name, address, limit_key;
