-- The principal (design, section 08): the one record of a person that Identity admits, which every
-- session, link and operation names. Its identifier is random and never reused, its authority
-- version only rises, and its name and copy of the address are removed when it is erased.

-- +goose Up
CREATE TABLE principal (
    id                text   PRIMARY KEY,
    state             text   NOT NULL CHECK (state IN ('active', 'disabled', 'erased')),
    authority_version bigint NOT NULL,
    revision          bigint NOT NULL,
    name              text,
    address           text,
    limit_key         text   NOT NULL UNIQUE
);

-- +goose Down
DROP TABLE principal;
