-- The link of a subject to its principal, the sessions, and the sign-in attempts (design section 08).
-- No cookie's value is stored, only its digest.

-- +goose Up
CREATE TABLE subject_link (
    issuer       text NOT NULL,
    subject      text NOT NULL,
    -- One link for a principal in phase 1.
    principal_id text NOT NULL UNIQUE REFERENCES principal (id),
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE session (
    digest        bytea       PRIMARY KEY,
    id            text        NOT NULL UNIQUE,
    principal_id  text        NOT NULL REFERENCES principal (id),
    login_session text        NOT NULL,
    signed_in_at  timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    ended_at      timestamptz,
    end_cause     text
);

CREATE TABLE sign_in_attempt (
    state_digest  bytea       PRIMARY KEY,
    cookie_digest bytea       NOT NULL,
    verifier      text        NOT NULL,
    nonce         text        NOT NULL,
    return_path   text        NOT NULL,
    expires_at    timestamptz NOT NULL
);

-- +goose Down
DROP TABLE sign_in_attempt;
DROP TABLE session;
DROP TABLE subject_link;
