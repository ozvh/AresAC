# Resource limits

Telemetry observers stop writing after socket backpressure until `drain`. Each observer's queued backlog is bounded by 512 frames and 1 MiB; overflow sends a reset so the console resynchronizes. A connection blocked for 30 seconds is disconnected.

Password changes admit three immediate attempts per account, refilling at six per minute. The source budget admits six immediate attempts, refilling at twelve per minute. Accounts share their budget across sessions. All password hashing and verification share a process-wide ceiling of four outstanding scrypt jobs, with no waiting queue. Account routes return 503 when that ceiling is occupied and 429 for exhausted attempt budgets.

Uploads default to 16 MiB and 64 live metadata records per customer, with global ceilings of 1 GiB and 4,096 live records. Rejected and quarantined records consume the record budget without consuming retained bytes. `UploadServiceConfig.quotas` can supply positive integer limits for deployments with different capacity needs. File writes require at least 64 MiB of remaining disk headroom.

Quota reservations are persisted in a SQLite transaction before asynchronous writes. Pending uploads and expired files still awaiting successful deletion count against quotas. Failed cleanup preserves the reservation for retry; successful cleanup releases it. Existing uploads count immediately, so a deployment already above a ceiling refuses new uploads until cleanup brings usage below the limit.

These controls apply after restarting the server with the updated source. They do not update a process that is already running.
