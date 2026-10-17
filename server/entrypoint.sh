#!/usr/bin/env bash

# Prevent inherited or command-line xtrace from disclosing secret expansions.
set +x
set -euo pipefail

if [[ -z "${FLAG_1:-}" ]]; then
  echo "ERROR: FLAG_1 is not set" >&2
  exit 1
fi

if [[ ! "$FLAG_1" =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "ERROR: FLAG_1 must be a 40-character hexadecimal value" >&2
  exit 1
fi

# Initialize the mounted flag placeholder.
if [[ ! -f "/app/flag" ]]; then
  echo "ERROR: /app/flag not found" >&2
  exit 1
fi

# Windows checkouts may copy CRLF line endings into the image. Normalize the
# placeholder file so the exact-line check below sees only the flag value.
sed -i 's/\r$//' /app/flag

if grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
  echo "Initializing server-container flag"
  sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_1}/g" /app/flag
fi

if ! grep -Fqx "$FLAG_1" "/app/flag"; then
  echo "ERROR: /app/flag was not initialized correctly" >&2
  exit 1
fi

# Start the WSGI server.
echo "Starting server..."
exec gunicorn -b 0.0.0.0:5000 --access-logfile - --error-logfile - server:app
