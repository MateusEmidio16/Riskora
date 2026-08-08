CREATE TABLE domains (
    id                  BIGSERIAL       PRIMARY KEY,
    organization_id     BIGINT          NOT NULL REFERENCES organizations(id),
    hostname            VARCHAR(255)    NOT NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_domains_hostname UNIQUE (hostname)
);
