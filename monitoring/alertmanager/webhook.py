"""Log Alertmanager webhooks and forward optional Telegram notifications."""

import html
import http.server
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

LOG_FILE = os.environ.get("ALERT_LOG_PATH", "/alerts/alerts.log")


def get_telegram_config():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    return token, chat_id


def send_telegram_alert(status, alert_name, severity, target, summary, description, now_str):
    bot_token, chat_id = get_telegram_config()
    if not bot_token or not chat_id:
        return

    icon = "🚨" if status == "FIRING" else "✅"
    color_tag = "🔴" if severity == "CRITICAL" else "🟡"

    msg_lines = [
        f"{icon} <b>[{status}] {color_tag} {html.escape(alert_name)}</b>",
        f"<b>Target:</b> <code>{html.escape(target)}</code>",
        f"<b>Severity:</b> {html.escape(severity)}",
        f"<b>Summary:</b> {html.escape(summary)}",
        f"<b>Description:</b> {html.escape(description)}",
        f"<b>Time:</b> {html.escape(now_str)}",
    ]
    message_text = "\n".join(msg_lines)

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": message_text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                sys.stderr.write(f"Telegram API response status {resp.status}: {resp.read()}\n")
            else:
                sys.stdout.write(f"Telegram notification sent for alert: {alert_name}\n")
    except Exception as e:  # noqa: BLE001 - Isolate notification delivery failures.
        sys.stderr.write(f"Failed to send Telegram alert: {e}\n")
    sys.stdout.flush()
    sys.stderr.flush()


class AlertWebhookHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)

        try:
            data = json.loads(post_body.decode("utf-8"))
            global_status = data.get("status", "unknown").upper()
            alerts = data.get("alerts", [])
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                for alert in alerts:
                    status = alert.get("status", global_status).upper()
                    labels = alert.get("labels", {})
                    annotations = alert.get("annotations", {})

                    alert_name = labels.get("alertname", "UnknownAlert")
                    severity = labels.get("severity", "unknown").upper()
                    summary = annotations.get("summary", "No summary provided")
                    description = annotations.get("description", "No description provided")
                    target = labels.get("name") or labels.get("instance") or labels.get("compose_service") or "tatou"

                    # Persist the alert and mirror it to stdout.
                    log_line = (
                        f"[{now_str}] [{status}] [{severity}] "
                        f"Alert: {alert_name} | Target: {target} | "
                        f"Summary: {summary} | Description: {description}\n"
                    )
                    f.write(log_line)
                    sys.stdout.write(log_line)

                    # Forward alerts when Telegram credentials are configured.
                    send_telegram_alert(
                        status=status,
                        alert_name=alert_name,
                        severity=severity,
                        target=target,
                        summary=summary,
                        description=description,
                        now_str=now_str
                    )

                f.flush()
                sys.stdout.flush()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        except Exception as e:  # noqa: BLE001 - Return JSON for request-processing failures.
            sys.stderr.write(f"Error processing webhook: {e}\n")
            sys.stderr.flush()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"error"}')

    def log_message(self, format, *args):
        # Keep stdout reserved for alert records.
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9095"))
    token, chat_id = get_telegram_config()
    telegram_status = "ENABLED" if (token and chat_id) else "DISABLED (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env)"
    print(f"Starting alert logger on port {port}", flush=True)
    print(f"Logging alerts to: {LOG_FILE}", flush=True)
    print(f"Telegram notifications: {telegram_status}", flush=True)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), AlertWebhookHandler)
    server.serve_forever()
