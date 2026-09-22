# Upgrade and rollback

1. Back up the Docker volumes before changing the image:
   `docker run --rm -v pingap-waf_pingap-data:/data -v "$PWD":/backup alpine tar czf /backup/pingap-data.tgz -C /data .`.
2. Keep `.env` unchanged; it contains the existing bootstrap credential and must
   not be regenerated during an upgrade.
3. Run `./scripts/upgrade-docker.sh`. Compose recreates the application while
   retaining the named data, backup, and etcd volumes.
4. Log in and verify domains, users, and WAF policy before removing the prior
   image.

If startup or a migration fails, stop the stack, preserve logs, restore the
volume archive into a new volume, and redeploy the prior image tag. Never delete
the original volume until the upgraded instance has passed the acceptance
checks. A migration is not considered complete until the populated-store
upgrade has been exercised in staging; this repository cannot claim live Docker
or prior-version migration validation without a Docker runtime and test data.
