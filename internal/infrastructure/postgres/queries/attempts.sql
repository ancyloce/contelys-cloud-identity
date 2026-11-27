-- name: InsertSignInAttempt :exec
INSERT INTO sign_in_attempt (state_digest, cookie_digest, verifier, nonce, return_path, expires_at)
VALUES (@state_digest, @cookie_digest, @verifier, @nonce, @return_path, @expires_at);

-- name: TakeSignInAttempt :one
-- An attempt is used once, and only by the browser whose cookie it is bound to: the state of another
-- browser's attempt finds nothing and leaves that attempt alone.
DELETE FROM sign_in_attempt
WHERE state_digest = @state_digest AND cookie_digest = @cookie_digest
RETURNING verifier, nonce, return_path, expires_at;
