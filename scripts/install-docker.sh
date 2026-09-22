#!/usr/bin/env sh
set -eu

: "${PINGAP_ADMIN_USER:=admin}"
: "${PINGAP_ADMIN_PASSWORD:?Set PINGAP_ADMIN_PASSWORD before installing}"
export PINGAP_ADMIN_USER PINGAP_ADMIN_PASSWORD

mkdir -p "${PINGAP_DATA_DIR:-./var/pingap}" "${PINGAP_BACKUP_DIR:-./var/pingap/backups}"
umask 077
printf '%s\n' "PINGAP_ADMIN_USER=${PINGAP_ADMIN_USER}" > .env
printf '%s\n' "PINGAP_ADMIN_PASSWORD=${PINGAP_ADMIN_PASSWORD}" >> .env
exec docker compose up -d --build
