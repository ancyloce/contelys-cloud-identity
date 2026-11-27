-- name: InsertSession :exec
INSERT INTO session (digest, id, principal_id, login_session, signed_in_at, last_seen_at)
VALUES (@digest, @id, @principal_id, @login_session, @signed_in_at, @signed_in_at);

-- name: FindLiveSession :one
-- The session of a cookie's digest that has not ended, with what admission needs of its principal.
SELECT s.id, s.principal_id, p.authority_version, p.limit_key
FROM session s
JOIN principal p ON p.id = s.principal_id
WHERE s.digest = @digest AND s.ended_at IS NULL;
