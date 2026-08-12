#!/bin/sh

set -eu

# Windows checkouts may expose CRLF through a bind mount. Normalize the reviewed
# provisioning script in memory; do not create or mutate a host-side copy.
tr -d '\r' < /opt/alpha-data/database/10-provision-database-roles.sh | sh
