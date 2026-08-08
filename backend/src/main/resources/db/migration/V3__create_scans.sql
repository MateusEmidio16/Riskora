CREATE TABLE scans (
    id              BIGSERIAL       PRIMARY KEY,
    domain_id       BIGINT          NOT NULL REFERENCES domains(id),
    status          VARCHAR(50)     NOT NULL DEFAULT 'PENDING',
    started_at      TIMESTAMP,
    finished_at     TIMESTAMP,
    score           INTEGER,
    created_at      TIMESTAMP       NOT NULL DEFAULT NOW()
);
