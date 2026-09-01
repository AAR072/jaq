#!/bin/bash
set -euo pipefail

umask 077
mkdir -p "$HOME"

# The controller owns analysis commands and uses docker exec. Keep this
# container alive without opening, parsing, or executing the supplied sample.
exec /bin/sleep infinity
