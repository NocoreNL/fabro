-- no-transaction
-- Rebuild `environments` to (a) allow provider='aca' and (b) add [aca] columns.
-- The provider CHECK cannot be altered in place; this is the SQLite 12-step
-- table rebuild. `environments` has an inbound FK (automations.environment_id
-- REFERENCES environments(id) ON DELETE RESTRICT), and PRAGMA foreign_keys is a
-- no-op inside a transaction, so this migration runs WITHOUT the sqlx-wrapped
-- transaction and manages foreign_keys itself.
PRAGMA foreign_keys=OFF;

CREATE TABLE environments_new (
    id TEXT PRIMARY KEY NOT NULL,
    revision TEXT NOT NULL,
    provider TEXT NOT NULL,
    cwd TEXT,
    image_docker TEXT,
    image_dockerfile_inline TEXT,
    resources_cpu INTEGER,
    resources_memory TEXT,
    resources_disk TEXT,
    network_mode TEXT NOT NULL,
    network_allow_json TEXT NOT NULL DEFAULT '[]',
    lifecycle_preserve INTEGER NOT NULL,
    lifecycle_stop_on_terminal INTEGER NOT NULL,
    lifecycle_auto_stop TEXT,
    labels_json TEXT NOT NULL DEFAULT '{}',
    env_json TEXT NOT NULL DEFAULT '{}',
    aca_region TEXT,
    aca_resource_group TEXT,
    aca_sandbox_group TEXT,
    aca_disk TEXT,
    aca_region_override INTEGER NOT NULL DEFAULT 0,
    aca_egress_allow_json TEXT NOT NULL DEFAULT '[]',
    aca_egress_traffic_inspection TEXT,
    aca_auto_suspend TEXT,
    CHECK (length(id) BETWEEN 1 AND 63),
    CHECK (substr(id, 1, 1) GLOB '[a-z0-9]'),
    CHECK (id NOT GLOB '*[^a-z0-9-]*'),
    CHECK (id <> 'local'),
    CHECK (length(revision) = 64),
    CHECK (revision NOT GLOB '*[^0-9a-f]*'),
    CHECK (provider IN ('local', 'docker', 'daytona', 'aca')),
    CHECK (network_mode IN ('allow_all', 'block', 'cidr_allow_list')),
    CHECK (lifecycle_preserve IN (0, 1)),
    CHECK (lifecycle_stop_on_terminal IN (0, 1)),
    CHECK (aca_region_override IN (0, 1)),
    CHECK (json_valid(network_allow_json)),
    CHECK (json_valid(labels_json)),
    CHECK (json_valid(env_json)),
    CHECK (json_valid(aca_egress_allow_json))
);

INSERT INTO environments_new (
    id, revision, provider, cwd, image_docker, image_dockerfile_inline,
    resources_cpu, resources_memory, resources_disk, network_mode,
    network_allow_json, lifecycle_preserve, lifecycle_stop_on_terminal,
    lifecycle_auto_stop, labels_json, env_json
)
SELECT
    id, revision, provider, cwd, image_docker, image_dockerfile_inline,
    resources_cpu, resources_memory, resources_disk, network_mode,
    network_allow_json, lifecycle_preserve, lifecycle_stop_on_terminal,
    lifecycle_auto_stop, labels_json, env_json
FROM environments;

DROP TABLE environments;
ALTER TABLE environments_new RENAME TO environments;

PRAGMA foreign_key_check;   -- must return no rows
PRAGMA foreign_keys=ON;
