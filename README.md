# tatou
A web platform for PDF watermarking. This project is intended for pedagogical use and may contain security vulnerabilities. Do not deploy on an open network.

## Contents

- [Setup](#prerequisites-and-python-setup)
- [Local CLI](#local-cli)
- [Web deployment](#deploy)
- [RMAP](#enable-rmap)
- [Monitoring](#monitoring-stack)
- [Development checks](#development-checks)
- [Extending watermarking methods](#add-a-watermarking-method)
- [Contributing](#contributing)

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/chirichexe/tatou-2026.git
cd tatou-2026
```

Fork the repository first if you plan to contribute changes.

### Contributing

`main` is protected: do not push to it directly. Work on a separate branch
named after its purpose, with one of these prefixes:

- `feat/<name>` for a new feature (e.g. `feat/davide-watermark-rmap`)
- `fix/<name>` for a bug fix (e.g. `fix/expose-group13-watermark`)
- `docs/<name>` for documentation only changes
- `chore/<name>` for maintenance, dependencies, CI

Open a pull request against `main`; CI (lint and tests) must pass before merging.

### Prerequisites and Python setup

The local CLI requires Python 3.12, Git, and pip. Install Tesseract OCR to recover
visible labels when QR extraction is unavailable. Docker deployment requires
Docker Engine and Docker Compose v2 with support for `include`.

From the repository root, install the runtime dependencies and activate the CLI:

```bash
python3.12 -m venv server/.venv
server/.venv/bin/python -m pip install -r server/requirements.txt -e ./server
source server/.venv/bin/activate
```

Activate the environment again in each new terminal before using `pdfwm`,
`rmap-keygen`, or `rmap-client`. The local watermarking CLI does not require
Docker, a database, or a deployment signing key.

### Local CLI

List the available methods and choose one that fits the source PDF:

```bash
pdfwm methods
pdfwm embed --help
```

| Method | Carrier |
|---|---|
| `davide-watermark` | PDF images |
| `francesco-watermark` | QR codes and encrypted visible labels |
| `khaled-text-spacing-watermark` | Selectable text glyph spacing |
| `group13-watermark` | Combined image, text-spacing, and QR layers |

Embed a watermark and verify it using the same method and key:

```bash
pdfwm embed input.pdf marked.pdf --method group13-watermark --key-prompt
pdfwm extract marked.pdf --method group13-watermark --key-prompt
```

Embedding prompts for the key and secret. Verification prints `Watermark verified`
without revealing the secret. Both commands require `--method`; there is no
default. `group13-watermark` requires a suitable image or enough selectable text;
use `francesco-watermark` for PDFs that only support a visual overlay.

For automated use, pass `--key-file path/to/key.txt` and, when embedding,
`--secret-file path/to/secret.txt` instead of interactive prompts. Keep those
files private. The key file's trailing line endings are trimmed; the secret
file's contents are preserved.

Export PDF structure and metadata as JSON:

```bash
pdfwm explore input.pdf --out tree.json
```

Object fingerprints in this output are diagnostic values, not authentication tokens.
See [API documentation](server/API.md) for HTTP endpoints and attribution behavior.

### Development checks

From the repository root, install the development tools and run the full suite
and lint checks:

```bash
make setup
make test
make lint
```

`make setup` installs development dependencies into `server/.venv`.
`make test` runs all tests with a temporary signing key; no running application
is required.

#### Unit and component tests

To run individual groups, activate the environment and create a temporary test
signing key. Start from the repository root:

```bash
source server/.venv/bin/activate
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Run unit and component tests for watermarking, the CLI, and test tooling:

```bash
(cd server && python -m pytest test/watermarking/ test/tooling/)
```

The watermarking group includes unit tests and integration tests that exercise
real PDF, cryptography, QR, and OCR components.

#### API and RMAP tests

In the same terminal, run the HTTP API tests or the RMAP integration tests:

```bash
(cd server && python -m pytest test/api/)
(cd server && python -m pytest test/rmap/)
```

These tests use Flask's test client, temporary storage, and mostly SQLite; they
do not require a deployed server. Tesseract is needed for OCR checks. Ghostscript
and a dedicated MariaDB test database enable optional integration cases. Skips
and expected failures are reported separately from passing tests.

#### Coverage analysis

From the repository root, run the complete suite with statement and branch
coverage, print missing lines, and generate an HTML report:

```bash
make coverage
make coverage-report
make coverage-html
```

`make coverage` replaces the previous coverage data. The other two commands read
the saved data without rerunning tests. Open `server/htmlcov/index.html` for the
detailed report. Coverage data and the `htmlcov/` directory are ignored by Git.

### Add a watermarking method

Put each concrete method in its own module under `server/src/watermarking_methods/`
and implement the `WatermarkingMethod` interface in `server/src/watermarking_method.py`.
Register the method explicitly in `server/src/watermarking_utils.py`; the server and
CLI use that registry, and no modules are loaded dynamically. Keep method-specific
tests under `server/test/watermarking/` (one folder per larger method, e.g.
`davide/`), next to the shared contract and CLI tests. HTTP tests live in
`server/test/api/` and RMAP tests in `server/test/rmap/`. `toy-eof` is not
registered: `server/test/conftest.py` registers it only for the tests that
need a fast method.

### Deploy

From the root of the directory:

Configure MariaDB and Grafana credentials in `.env`, and replace `FLAG_1` with
exactly 40 hexadecimal characters. For an isolated local deployment, generate
a fresh value with `python3 -c 'import secrets; print(secrets.token_hex(20))'`;
the university deployment must use its assigned flag. Keep all real values
private. Configure RMAP separately as described below.

```bash
cp sample.env .env

# Generate a signing key and copy it into SECRET_KEY in .env.
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Edit `.env` to set the credentials, signing key, and flag before starting the stack:

```bash
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:5000/healthz
docker compose logs -f server
```

Open [Tatou](http://127.0.0.1:5000) to create an account, upload a PDF, and issue
watermarked versions. Press Ctrl-C to stop following logs. To stop the stack
while preserving its database and document volumes:

```bash
docker compose down
```

### Monitoring Stack

The project includes a monitoring and logging stack based on Prometheus, Grafana, Loki, Promtail, and cAdvisor:

- **Grafana**: [http://127.0.0.1:3000](http://127.0.0.1:3000) (pre-configured with Prometheus & Loki datasources and the *Tatou Monitoring & Logs Overview* dashboard)
- **Prometheus**: [http://127.0.0.1:9090](http://127.0.0.1:9090)
- **Loki**: [http://127.0.0.1:3100](http://127.0.0.1:3100)
- **cAdvisor**: [http://127.0.0.1:8081](http://127.0.0.1:8081)

To browse logs, open Grafana at [http://127.0.0.1:3000](http://127.0.0.1:3000) and visit **Dashboards** > **Tatou Monitoring & Logs Overview**, or use **Explore** with the Loki data source. For more details, see [monitoring configuration](#monitoring-configuration).


The standard deployment starts the application and MariaDB. MariaDB is
available only to the application through Docker's internal backend network;
it does not publish a port on the host.

phpMyAdmin is commented out in the current Compose file; no active admin profile
is provided.

For direct database administration without publishing MariaDB, use
`docker compose exec db mariadb -u root -p` and enter the root password from
the local `.env` file when prompted.

`SECRET_KEY` is required: Compose and the application reject an unset or empty
key, and the application rejects the former public development key. Keep
`sample.env` empty for this setting and never commit the real `.env` file.
Each developer should generate a separate local key. Generate the university
deployment's key once, store it privately on that server, and reuse it across
restarts and all server workers. Changing it invalidates existing login tokens,
so users must log in again.

PDF uploads are limited to 64 MiB by default. Set `MAX_UPLOAD_SIZE_BYTES` in
the local `.env` file to a different positive byte value when the deployment
requires another limit. Requests or documents above the configured limit are
rejected with HTTP `413` before PDF processing or database insertion.

For direct Python runs, export `SECRET_KEY` in the process environment; the
application does not load `.env` itself. The test command above creates a
temporary test key and does not need the deployment key.

Login allows five failed attempts per account and per connection IP in a rolling
60-second window. The next attempt returns HTTP 429 and `Retry-After` (at most
60 seconds); blocked retries never extend the cooldown. Successful logins do not
consume the failure budget, and existing tokens continue to work.

The counters use Python's built-in SQLite in
`STORAGE_DIR/.auth/login-attempts.sqlite3`. The existing storage volume shares
them across Gunicorn workers and preserves them across container recreation.
Expired entries are removed on subsequent attempts. Account/IP keys are HMAC
digests, and passwords are never stored in the counter database. Storage errors
return a generic 503 rather than disabling throttling. No MariaDB migration or
additional service is required. Multiple replicas must share this local storage;
this implementation is intended for the single-host course deployment.

IP limits use the direct connection address. Do not enable trust in arbitrary
`X-Forwarded-For` headers. If a reverse proxy is introduced, configure trusted
proxy handling explicitly; otherwise all clients behind it share one IP budget.

### Enable RMAP

Tatou uses the upstream [RMAP v1.0.2](https://github.com/nharrand/RMAP) package
for the PGP challenge/response protocol. The feature stays disabled until its
key paths are configured. Create the server keypair locally, then place the
course-provided client public keys in `rmap-keys/clients`, named after their
identities (for example, `Group_01.asc`). Keep private keys outside Git. For a
server deployment, keep the entire key directory outside the checkout and set
`RMAP_KEYS_HOST_DIR` to that absolute host path; Compose mounts it read-only at
`/app/rmap-keys`.

```bash
mkdir -p rmap-keys/clients
rmap-keygen --name "Tatou server" --email server@example.test \
  --out-private rmap-keys/server_private.asc \
  --out-public rmap-keys/server_public.asc
chmod 600 rmap-keys/server_private.asc
```

Set these values in `.env` for Compose:

```dotenv
RMAP_SERVER_PUBLIC_KEY_PATH=/app/rmap-keys/server_public.asc
RMAP_SERVER_PRIVATE_KEY_PATH=/app/rmap-keys/server_private.asc
RMAP_CLIENT_KEYS_DIR=/app/rmap-keys/clients
RMAP_DOCUMENT_ID=42
RMAP_WATERMARK_METHOD=group13-watermark
RMAP_WATERMARK_KEY=<private-watermark-key>
RMAP_SERVER_KEY_PASSPHRASE_FILE=
```

For example, a server keeping its keys in `/home/softsec/secrets` can use:

```dotenv
RMAP_KEYS_HOST_DIR=/home/softsec/secrets
RMAP_SERVER_PUBLIC_KEY_PATH=/app/rmap-keys/public_key.asc
RMAP_SERVER_PRIVATE_KEY_PATH=/app/rmap-keys/private_key.asc
RMAP_CLIENT_KEYS_DIR=/app/rmap-keys/clients
RMAP_SERVER_KEY_PASSPHRASE_FILE=
```

`RMAP_DOCUMENT_ID` is the confidential source document already stored in Tatou.
Every completed handshake produces a new version, watermarked with the peer's
session link as its sole watermark secret, records the peer identity separately
as version metadata, and returns the generated link. RMAP defaults to
`group13-watermark` for newly issued copies. The manual watermark interface offers four choices: each of the three
component methods individually, or the combined method. Operators can still
override `RMAP_WATERMARK_METHOD` for RMAP. The component methods are listed in
the [CLI method table](#local-cli).

Layers that do not fit the PDF are skipped, and the combined reader can still
read copies carrying a compatible component layer. The fingerprint attributes
cropped, rescaled or screenshotted leaks through `read-watermark`.
`toy-eof` is easily stripped and kept only for the test suite.

When the server private key has a passphrase, create
`rmap-keys/server_passphrase` locally with mode `600`, place the passphrase in
that file, and set `RMAP_SERVER_KEY_PASSPHRASE_FILE` to
`/app/rmap-keys/server_passphrase`. Keep `RMAP_SERVER_KEY_PASSPHRASE` empty.
The container receives
the key directory read-only and the passphrase is never included in the Compose
environment.

The upstream CLI can exercise the complete flow with the client keypair:

```bash
rmap-client --url http://localhost:5000 --identity Group_01 \
  --client-private-key path/to/group01_private.asc \
  --server-public-key rmap-keys/server_public.asc \
  --msg1-path /api/rmap-initiate --msg2-path /api/rmap-get-link \
  --get-link-path /api/get-version --fetch-link
```

The reference `RMAPServer` keeps pending nonces in process memory. The
provided Gunicorn command uses one worker; if you add workers or replicas,
route both handshake messages to the same process or provide shared session
state.

### Monitoring configuration

Monitoring configuration and operations:

The `monitoring/` directory provides the monitoring, alerting, and log aggregation stack for Tatou:

- **Prometheus** (Port `9090`): Time-series database scraping metrics from containers and evaluating alert rules.
- **Alertmanager** (Port `9093`): Alert routing engine dispatching notifications for attacks and system errors.
- **Alert Logger Webhook** (Port `9095`): Lightweight receiver logging all alerts to `monitoring/alertmanager/alerts.log`.
- **Grafana** (Port `3000`): Web dashboard UI pre-configured with Loki, Prometheus, and Alertmanager datasources.
- **Loki** (Port `3100`): Log aggregation engine receiving log streams.
- **Promtail**: Daemon reading Docker container logs via Docker engine socket and forwarding them with labels to Loki and extracting alert metrics.
- **cAdvisor** (Port `8081`): Container metrics exporter providing CPU, memory, filesystem, and network statistics per container.

---

#### Access URLs

| Service | URL | Default Credentials |
| :--- | :--- | :--- |
| **Grafana** | [http://localhost:3000](http://localhost:3000) | Configured via `GF_USERNAME` and `GF_PASSWORD` in `.env` |
| **Prometheus** | [http://localhost:9090](http://localhost:9090) | No auth required |
| **Alertmanager** | [http://localhost:9093](http://localhost:9093) | No auth required |
| **Loki** | [http://localhost:3100](http://localhost:3100) | No auth required |
| **cAdvisor** | [http://localhost:8081](http://localhost:8081) | No auth required |

---

#### Resource Limits (CPU & RAM)

All monitoring services have strict resource limits configured in [docker-compose.monitoring.yml](docker-compose.monitoring.yml):

| Service | CPU Limit | RAM Limit | CPU Reservation | RAM Reservation |
| :--- | :--- | :--- | :--- | :--- |
| **prometheus** | `0.50` (50%) | `512MB` | `0.10` | `128MB` |
| **loki** | `0.50` (50%) | `512MB` | `0.10` | `128MB` |
| **grafana** | `0.50` (50%) | `512MB` | `0.10` | `128MB` |
| **cadvisor** | `0.30` (30%) | `256MB` | `0.05` | `64MB` |
| **promtail** | `0.25` (25%) | `256MB` | `0.05` | `64MB` |
| **alertmanager** | `0.25` (25%) | `128MB` | `0.05` | `32MB` |
| **alert-logger** | `0.10` (10%) | `64MB` | `0.02` | `16MB` |

---

#### Alerting: Attacks and Errors

Alertmanager receives alerts generated by Prometheus using the rules in [monitoring/prometheus/alert.rules.yml](monitoring/prometheus/alert.rules.yml):

##### 1. Attack Detection Alerts
- **BruteForceOrAuthAttack**: Detects spikes in failed authentication attempts or HTTP `429 Too Many Requests` responses from the rate limiter.
- **PotentialDoS_HighCpu**: Detects sustained container CPU usage above 80%, which may indicate a DoS attack, loop or excessive computation.
- **PotentialDDoS_NetworkFlood**: Detects incoming container network traffic above 10 MB/s.
- **HighMemoryExhaustion**: Detects RAM usage above 450 MB, which may indicate memory exhaustion from decompression or large uploads.

##### 2. System Error Alerts
- **ServiceDown**: A monitored target is unreachable (`up == 0`).
- **ContainerCrashOrRestart**: Detects container restarts or crashes.
- **HighServerErrorRate**: Detects spikes in HTTP 5xx errors or unhandled Flask server exceptions.
- **DatabaseErrors**: Detects errors reported by MariaDB.

---

#### File Notifications (`alerts.log`)

Alertmanager sends notifications to `alert-logger`, a local webhook on port 9095 that writes formatted, timestamped entries to this file:

```bash
# Follow alerts in real time
tail -f monitoring/alertmanager/alerts.log
```

Example log entry:
```text
[2026-09-21 11:45:00 UTC] [FIRING] [CRITICAL] Alert: BruteForceOrAuthAttack | Target: tatou-2026-server-1 | Summary: Potential Brute-Force / Credential Stuffing Attack | Description: Detected spike in authentication failures or 429 rate limit triggers on Tatou server.
```

---

#### Connect a Telegram Channel

Telegram credentials are read from `.env`:

1. Open `.env` and set:
   ```bash
   TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
   TELEGRAM_CHAT_ID=-1001234567890
   ```
2. Apply the changes:
   ```bash
   docker compose up -d alert-logger
   ```
   *The `alert-logger` service writes alerts to the file and sends them to Telegram using HTML formatting.*

---

#### How to Start & Stop

##### Option 1: Together with Tatou (Default)

```bash
# Start application and monitoring stack
docker compose up -d

# View status of all containers
docker compose ps

# Stop all containers
docker compose down
```

##### Option 2: Run Monitoring Stack Separately

```bash
# Start only monitoring services
docker compose -f docker-compose.monitoring.yml up -d

# Stop only monitoring services
docker compose -f docker-compose.monitoring.yml down
```

---

#### Configuration Files

```text
monitoring/
├── alertmanager/
│   ├── alertmanager.yml                      # Alertmanager routes, webhooks & Telegram configs
│   ├── webhook.py                            # Webhook script logging alerts to file
│   └── alerts.log                            # Destination log file for alerts
├── prometheus/
│   ├── prometheus.yml                        # Scrape jobs & alerting configuration
│   └── alert.rules.yml                       # Alerting rules for attacks and errors
├── loki/
│   └── loki-config.yaml                      # Loki TSDB & storage configuration
├── promtail/
│   └── promtail-config.yaml                  # Promtail Docker discovery and log forwarding config
└── grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── datasources.yaml              # Auto-provisions Prometheus, Loki, Alertmanager
    │   └── dashboards/
    │       └── dashboards.yaml               # Auto-provisions dashboards
    └── dashboards/
        └── tatou-overview.json               # Pre-built monitoring & logs dashboard
```
