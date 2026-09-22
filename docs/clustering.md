# Clustering via etcd peers

Pingap nodes are symmetric peers. Configuration is committed to the configured etcd backend and each peer observes it through the existing configuration watch; no node is a master or slave, and no per-node API key or push endpoint exists.

Each node may publish a heartbeat under `_cluster/nodes/`. The identity is a stable SHA-256-derived value from deployment configuration, not a hostname or address. Heartbeats include software version, applied config version and hash, resource usage, and `last_seen`.

Liveness is timestamp based. A peer is offline after the configured offline threshold (the default primitive is 30 seconds), and is stale when its applied config version differs from the current committed version. A hash mismatch is reported as drift, separately from convergence lag. Because the storage interface has no lease support, stale entries are reaped after a longer retention threshold (default primitive: one day) by whichever peer observes them. Reaping removes only the inventory key; it never removes configuration.

The data plane continues serving its local materialised configuration when etcd is unavailable. Administration should report the cluster as degraded rather than turn an etcd outage into request-path failure. Operators should treat a node marked stale or drifted as not converged until its status returns healthy.

Etcd contains configuration and cluster metadata and must use TLS and authentication on a private network. Peer symmetry means compromise of one node permits writes to shared configuration; this is an intentional trade-off and not a substitute for securing every peer.
