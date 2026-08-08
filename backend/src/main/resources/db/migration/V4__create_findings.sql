CREATE TABLE findings (
    id                  BIGSERIAL       PRIMARY KEY,
    scan_id             BIGINT          NOT NULL REFERENCES scans(id),
    category            VARCHAR(100)    NOT NULL,
    severity            VARCHAR(50)     NOT NULL,
    title               VARCHAR(500)    NOT NULL,
    description         TEXT,
    recommendation      TEXT,
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW()
);
