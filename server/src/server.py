import hashlib
import os
import secrets
import sqlite3
import stat
from functools import wraps
from pathlib import Path
from uuid import uuid4

import fitz
from flask import Flask, g, jsonify, request, send_file
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pymupdf.mupdf import FzErrorFormat
from rmap import RMAPError, RMAPServer
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import watermarking_utils as WMUtils
from login_rate_limit import LoginRateLimited, LoginRateLimiter
from watermarking_method import WatermarkingError

DEFAULT_MAX_UPLOAD_SIZE_BYTES = 64 * 1024 * 1024
MULTIPART_OVERHEAD_BYTES = 1024 * 1024


class UploadTooLargeError(Exception):
    """Raised when an uploaded document exceeds the configured byte limit."""


def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY", "").strip()

    if not secret_key or secret_key == "dev-secret-change-me":  # noqa: S105 - rejects the old sample value
        raise RuntimeError("Set SECRET_KEY to a private, randomly generated value")

    app.config["SECRET_KEY"] = secret_key
    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
    app.config["MAX_UPLOAD_SIZE_BYTES"] = int(os.environ.get(
        "MAX_UPLOAD_SIZE_BYTES", str(DEFAULT_MAX_UPLOAD_SIZE_BYTES),
    ))
    if app.config["MAX_UPLOAD_SIZE_BYTES"] <= 0:
        raise RuntimeError("MAX_UPLOAD_SIZE_BYTES must be a positive integer")

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")
    app.config["RMAP_SERVER_PUBLIC_KEY_PATH"] = os.environ.get(
        "RMAP_SERVER_PUBLIC_KEY_PATH", ""
    ).strip()
    app.config["RMAP_SERVER_PRIVATE_KEY_PATH"] = os.environ.get(
        "RMAP_SERVER_PRIVATE_KEY_PATH", ""
    ).strip()
    app.config["RMAP_CLIENT_KEYS_DIR"] = os.environ.get(
        "RMAP_CLIENT_KEYS_DIR", ""
    ).strip()
    app.config["RMAP_SERVER_KEY_PASSPHRASE"] = os.environ.get(
        "RMAP_SERVER_KEY_PASSPHRASE"
    )
    app.config["RMAP_SERVER_KEY_PASSPHRASE_FILE"] = os.environ.get(
        "RMAP_SERVER_KEY_PASSPHRASE_FILE", ""
    ).strip()
    app.config["RMAP_DOCUMENT_ID"] = os.environ.get("RMAP_DOCUMENT_ID", "").strip()
    app.config["RMAP_WATERMARK_METHOD"] = os.environ.get(
        "RMAP_WATERMARK_METHOD", "group13-watermark"
    ).strip() or "group13-watermark"
    app.config["RMAP_WATERMARK_KEY"] = os.environ.get(
        "RMAP_WATERMARK_KEY", ""
    )
    app.config["RMAP_WATERMARK_POSITION"] = os.environ.get(
        "RMAP_WATERMARK_POSITION", ""
    ).strip() or None

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    login_limiter = LoginRateLimiter(
        app.config["STORAGE_DIR"] / ".auth" / "login-attempts.sqlite3", secret_key,
    )

    rmap_key_settings = (
        app.config["RMAP_SERVER_PUBLIC_KEY_PATH"],
        app.config["RMAP_SERVER_PRIVATE_KEY_PATH"],
        app.config["RMAP_CLIENT_KEYS_DIR"],
    )
    if any(rmap_key_settings):
        if (
            app.config["RMAP_SERVER_KEY_PASSPHRASE"]
            and app.config["RMAP_SERVER_KEY_PASSPHRASE_FILE"]
        ):
            raise RuntimeError(
                "Use either RMAP_SERVER_KEY_PASSPHRASE or "
                "RMAP_SERVER_KEY_PASSPHRASE_FILE, not both"
            )
        if app.config["RMAP_SERVER_KEY_PASSPHRASE_FILE"]:
            passphrase_path = Path(app.config["RMAP_SERVER_KEY_PASSPHRASE_FILE"])
            try:
                passphrase_mode = stat.S_IMODE(passphrase_path.stat().st_mode)
                if passphrase_mode & (stat.S_IRWXG | stat.S_IRWXO):
                    raise RuntimeError(
                        "RMAP passphrase file must not be group- or world-accessible"
                    )
                passphrase = passphrase_path.read_text(encoding="utf-8").rstrip("\r\n")
            except OSError as error:
                raise RuntimeError("Could not read RMAP passphrase file") from error
            if not passphrase:
                raise RuntimeError("RMAP passphrase file must not be empty")
            app.config["RMAP_SERVER_KEY_PASSPHRASE"] = passphrase
    if any(rmap_key_settings) and not all(rmap_key_settings):
        raise RuntimeError(
            "RMAP requires RMAP_SERVER_PUBLIC_KEY_PATH, "
            "RMAP_SERVER_PRIVATE_KEY_PATH, and RMAP_CLIENT_KEYS_DIR"
        )
    if all(rmap_key_settings):
        if not (
            app.config["RMAP_DOCUMENT_ID"]
            and app.config["RMAP_WATERMARK_METHOD"]
            and app.config["RMAP_WATERMARK_KEY"]
        ):
            raise RuntimeError(
                "RMAP requires RMAP_DOCUMENT_ID, RMAP_WATERMARK_METHOD, "
                "and RMAP_WATERMARK_KEY"
            )
        try:
            app.config["RMAP_DOCUMENT_ID"] = int(app.config["RMAP_DOCUMENT_ID"])
        except ValueError as error:
            raise RuntimeError("RMAP_DOCUMENT_ID must be a positive integer") from error
        if app.config["RMAP_DOCUMENT_ID"] <= 0:
            raise RuntimeError("RMAP_DOCUMENT_ID must be a positive integer")
        rmap_server = RMAPServer(
            server_public_key_path=app.config["RMAP_SERVER_PUBLIC_KEY_PATH"],
            server_private_key_path=app.config["RMAP_SERVER_PRIVATE_KEY_PATH"],
            passphrase=app.config["RMAP_SERVER_KEY_PASSPHRASE"],
            logger=app.logger,
        )
        rmap_server.loadIdentities(app.config["RMAP_CLIENT_KEYS_DIR"])
    else:
        rmap_server = None
    app.config["RMAP_SERVER"] = rmap_server

    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def _log_internal_failure(context: str, error: Exception) -> None:
        app.logger.warning(
            "%s failed (%s)", context, type(error).__name__,
        )

    def _internal_error_response(
        context: str,
        error: Exception,
        public_message: str,
        status: int,
    ):
        _log_internal_failure(context, error)
        return jsonify({"error": public_message}), status

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _save_upload_with_limit(file, path: Path) -> None:
        remaining = app.config["MAX_UPLOAD_SIZE_BYTES"]
        with path.open("xb") as output:
            while True:
                chunk = file.stream.read(min(1024 * 1024, remaining + 1))
                if not chunk:
                    return
                if len(chunk) > remaining:
                    raise UploadTooLargeError
                output.write(chunk)
                remaining -= len(chunk)

    def _is_valid_pdf(path: Path) -> bool:
        try:
            if path.stat().st_size == 0:
                return False
            with path.open("rb") as source:
                if source.read(5) != b"%PDF-":
                    return False
            with fitz.open(str(path)) as document:
                if document.needs_pass or document.is_encrypted:
                    return False
                if document.page_count < 1:
                    return False
                for page_number in range(document.page_count):
                    try:
                        document.load_page(page_number)
                        return True
                    except (RuntimeError, ValueError, FzErrorFormat):
                        continue
                return False
        except (
            fitz.EmptyFileError,
            fitz.FileDataError,
            OSError,
            RuntimeError,
            ValueError,
            FzErrorFormat,
        ):
            return False

    def _remove_file(path: Path | None) -> None:
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            _log_internal_failure("file cleanup", error)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        if isinstance(error, RequestEntityTooLarge):
            return jsonify({"error": "document exceeds maximum upload size"}), 413
        if isinstance(error, HTTPException):
            if not request.path.startswith("/api/"):
                return error
            status = error.code or 500
            message = (
                "internal server error" if status >= 500 else "request failed"
            )
            _log_internal_failure("HTTP request", error)
            return jsonify({"error": message}), status
        _log_internal_failure("unhandled request", error)
        return jsonify({"error": "internal server error"}), 500

    # Browsers do not attach bearer Authorization headers to cross-site requests automatically.

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except SQLAlchemyError:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    def _rmap_unavailable_response():
        return jsonify({"error": "RMAP is not configured"}), 503

    # RMAP message 1: encrypted {identity, nonceClient} -> encrypted {nonceClient, nonceServer}.
    # The RMAP package owns all PGP handling and handshake state; this application only exposes
    # its HTTP boundary.
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        if rmap_server is None:
            return _rmap_unavailable_response()
        message = request.get_json(silent=True)
        if not isinstance(message, dict):
            return jsonify({"error": "RMAP message must be a JSON object"}), 400
        try:
            _, response = rmap_server.receiveMsg1(message)
        except (RMAPError, KeyError, TypeError, ValueError) as error:
            _log_internal_failure("RMAP message 1", error)
            return jsonify({"error": "invalid RMAP message"}), 400
        return jsonify(response), 200

    # RMAP message 2: create a fresh, watermarked copy of the confidential document and record
    # it under the completed protocol link.
    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        if rmap_server is None:
            return _rmap_unavailable_response()
        message = request.get_json(silent=True)
        if not isinstance(message, dict):
            return jsonify({"error": "RMAP message must be a JSON object"}), 400
        try:
            identity, expected_link, response = rmap_server.receiveMsg2(message)
        except (RMAPError, KeyError, TypeError, ValueError) as error:
            _log_internal_failure("RMAP message 2", error)
            return jsonify({"error": "invalid RMAP message"}), 400

        try:
            with get_engine().connect() as conn:
                source = conn.execute(
                    text("""
                        SELECT id, name, path FROM Documents
                        WHERE id = :id
                        LIMIT 1
                    """),
                    {"id": app.config["RMAP_DOCUMENT_ID"]},
                ).first()
                link_exists = conn.execute(
                    text("SELECT 1 FROM Versions WHERE link = :link LIMIT 1"),
                    {"link": expected_link},
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "RMAP document lookup", error,
                "service temporarily unavailable", 503,
            )
        if not source:
            return jsonify({"error": "RMAP document not found"}), 404
        if link_exists:
            return jsonify({"error": "RMAP session already completed"}), 409

        output_path = None
        output_path_reserved = False
        try:
            source_path = _safe_resolve_under_storage(
                source.path, app.config["STORAGE_DIR"],
            )
            if not source_path.is_file():
                return jsonify({"error": "RMAP document missing on disk"}), 410
            watermark_secret = expected_link
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(source_path),
                secret=watermark_secret,
                key=app.config["RMAP_WATERMARK_KEY"],
                method=app.config["RMAP_WATERMARK_METHOD"],
                position=app.config["RMAP_WATERMARK_POSITION"],
                intended_for=identity,
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or not wm_bytes:
                raise RuntimeError("watermarking returned no document")
            output_dir = _safe_resolve_under_storage(
                source_path.parent / "rmap", app.config["STORAGE_DIR"],
            )
            output_dir.mkdir(parents=True, exist_ok=True)
            filename = f"rmap-{expected_link}.pdf"
            output_path = _safe_resolve_under_storage(output_dir / filename, output_dir)
            with output_path.open("xb") as output:
                output_path_reserved = True
                output.write(wm_bytes)
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            if output_path_reserved:
                _remove_file(output_path)
            return _internal_error_response(
                "RMAP watermark creation", error, "could not create watermarked version", 500,
            )

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": int(source.id),
                        "link": expected_link,
                        "intended_for": identity,
                        "secret": watermark_secret,
                        "method": app.config["RMAP_WATERMARK_METHOD"],
                        "position": app.config["RMAP_WATERMARK_POSITION"] or "",
                        "path": str(output_path),
                    },
                )
        except SQLAlchemyError as error:
            _remove_file(output_path)
            return _internal_error_response(
                "RMAP version database operation", error,
                "service temporarily unavailable", 503,
            )

        return jsonify(response), 200

    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            with get_engine().begin() as conn:
                res = conn.execute(
                    text("INSERT INTO Users (email, hpassword, login) VALUES (:email, :hpw, :login)"),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except SQLAlchemyError as error:
            return _internal_error_response(
                "create user database operation", error,
                "service temporarily unavailable", 503,
            )

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "email and password must be strings"}), 400
        email = payload.get("email", "")
        password = payload.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify({"error": "email and password must be strings"}), 400
        email = email.strip().lower()
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "login database operation", error,
                "service temporarily unavailable", 503,
            )

        # Known accounts use their numeric ID, including database-collation aliases of the
        # email. Unknown accounts receive the same failure budget.
        account = f"user:{row.id}" if row else f"email:{email.casefold()}"
        try:
            # The deployment connects directly to Gunicorn. Do not trust client-supplied
            # X-Forwarded-For / X-Real-IP headers.
            with login_limiter.attempt(account, request.remote_addr or "unknown") as attempt:
                if not row or not check_password_hash(row.hpassword, password):
                    attempt.failed = True
                    return jsonify({"error": "invalid credentials"}), 401
        except LoginRateLimited as error:
            response = jsonify({"error": "too many login attempts; try again shortly"})
            response.status_code = 429
            response.headers["Retry-After"] = str(error.retry_after)
            response.headers["Cache-Control"] = "no-store"
            return response
        except (sqlite3.Error, OSError) as error:
            # A failed limiter must not silently permit unlimited guesses.
            return _internal_error_response(
                "login rate-limit storage", error, "service temporarily unavailable", 503,
            )

        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        request.max_content_length = (
            app.config["MAX_UPLOAD_SIZE_BYTES"] + MULTIPART_OVERHEAD_BYTES
        )
        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        fname = secure_filename(file.filename)
        if (
            not fname.endswith(".pdf")
            or not fname[:-4]
            or fname.count(".") != 1
        ):
            return jsonify({"error": "lowercase .pdf extension required"}), 400

        final_name = request.form.get("name") or fname
        storage_root = app.config["STORAGE_DIR"]
        temporary_path = None
        stored_path = None
        stored_path_reserved = False
        try:
            user_dir = _safe_resolve_under_storage(
                storage_root / "files" / str(int(g.user["id"])),
                storage_root,
            )
            user_dir.mkdir(parents=True, exist_ok=True)
            upload_id = uuid4().hex
            temporary_path = _safe_resolve_under_storage(
                user_dir / f".upload-{upload_id}.tmp", user_dir,
            )
            _save_upload_with_limit(file, temporary_path)

            if not _is_valid_pdf(temporary_path):
                _remove_file(temporary_path)
                return jsonify({"error": "invalid PDF document"}), 400

            sha_hex = _sha256_file(temporary_path)
            size = temporary_path.stat().st_size
            stored_name = f"{upload_id}.pdf"
            stored_path = _safe_resolve_under_storage(
                user_dir / stored_name, user_dir,
            )
            # A same-filesystem hard link publishes the complete validated file atomically and
            # refuses to overwrite an existing UUID path.
            os.link(temporary_path, stored_path)
            stored_path_reserved = True
            temporary_path.unlink()
            temporary_path = None
        except UploadTooLargeError:
            _remove_file(temporary_path)
            return jsonify({"error": "document exceeds maximum upload size"}), 413
        except (RuntimeError, ValueError, OSError):
            _remove_file(temporary_path)
            if stored_path_reserved:
                _remove_file(stored_path)
            return jsonify({"error": "could not store document"}), 500

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """),
                    {"id": did},
                ).one()
        except SQLAlchemyError as error:
            _remove_file(stored_path)
            return _internal_error_response(
                "upload database operation", error,
                "service temporarily unavailable", 503,
            )

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "document list database operation", error,
                "service temporarily unavailable", 503,
            )

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200

    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=.
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.secret, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.ownerid = :uid AND d.id = :did
                    """),
                    {"uid": int(g.user["id"]), "did": document_id},
                ).all()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "version list database operation", error,
                "service temporarily unavailable", 503,
            )

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Users u
                        JOIN Documents d ON d.ownerid = u.id
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.ownerid = :uid
                    """),
                    {"uid": int(g.user["id"])},
                ).all()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "all versions database operation", error,
                "service temporarily unavailable", 503,
            )

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200

    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=.
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "document lookup database operation", error,
                "service temporarily unavailable", 503,
            )

        # Do not disclose documents owned by other users.
        if not row:
            return jsonify({"error": "document not found"}), 404

        try:
            file_path = _safe_resolve_under_storage(
                row.path, app.config["STORAGE_DIR"],
            )
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.is_file():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256.
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # Enables 304 if If-Modified-Since/Range handling.
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp

    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT *
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """),
                    {"link": link},
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "version lookup database operation", error,
                "service temporarily unavailable", 503,
            )

        # Do not disclose documents owned by other users.
        if not row:
            return jsonify({"error": "document not found"}), 404

        try:
            file_path = _safe_resolve_under_storage(
                row.path, app.config["STORAGE_DIR"],
            )
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.is_file():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256.
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # Enables 304 if If-Modified-Since/Range handling.
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative).
    def _safe_resolve_under_storage(p: str | Path, storage_root: Path) -> Path:
        if not isinstance(p, (str, Path)) or not str(p) or "\x00" in str(p):
            raise ValueError("invalid storage path")
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        if fp == storage_root or not fp.is_relative_to(storage_root):
            raise ValueError("path must stay inside the storage directory")
        return fp

    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience.
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        if document_id is None:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
            )

            if document_id is None and request.is_json:
                payload = request.get_json(silent=True)
                if not isinstance(payload, dict):
                    return jsonify({"error": "JSON object required"}), 400
                document_id = payload.get("id")

        try:
            if isinstance(document_id, bool) or not isinstance(
                document_id, (str, int)
            ):
                raise TypeError
            doc_id = int(document_id)
            if doc_id <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {
                        "id": doc_id,
                        "uid": int(g.user["id"]),
                    },
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "delete lookup database operation", error,
                "service temporarily unavailable", 503,
            )

        if not row:
            # Return the same response for missing and unauthorized documents.
            return jsonify({"error": "document not found"}), 404

        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_note = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                if not fp.is_file():
                    return jsonify({"error": "document path invalid"}), 500
                try:
                    fp.unlink()
                    file_deleted = True
                except OSError as error:
                    delete_note = "file deletion failed"
                    _log_internal_failure("document file deletion", error)
            else:
                file_missing = True
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE).
        try:
            with get_engine().begin() as conn:
                result = conn.execute(
                    text("""
                        DELETE FROM Documents
                        WHERE id = :id AND ownerid = :uid
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                )

                if result.rowcount != 1:
                    return jsonify({"error": "document not found"}), 404

        except SQLAlchemyError as error:
            return _internal_error_response(
                "document delete database operation", error,
                "service temporarily unavailable", 503,
            )

        return jsonify({
            "deleted": True,
            "id": doc_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
            "note": delete_note,
        }), 200

    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}

        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if (not method or not isinstance(intended_for, str) or not intended_for
                or not isinstance(secret, str) or not isinstance(key, str)):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400
        intended_slug = secure_filename(intended_for)[:60]
        if not intended_slug:
            return jsonify({"error": "invalid intended_for"}), 400
        visible_intended_for = " ".join(intended_for.split())[:60]

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
        except SQLAlchemyError as error:
            return _internal_error_response(
                "watermark document lookup", error,
                "service temporarily unavailable", 503,
            )

        if not row:
            return jsonify({"error": "document not found"}), 404

        try:
            file_path = _safe_resolve_under_storage(
                row.path, app.config["STORAGE_DIR"],
            )
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.is_file():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "invalid watermarking request"}), 400
        except (TypeError, ValueError, OSError, RuntimeError, WatermarkingError) as error:
            return _internal_error_response(
                "watermark applicability check", error,
                "invalid watermarking request", 400,
            )

        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position,
                intended_for=visible_intended_for,
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking failed"}), 500
        except (TypeError, ValueError, OSError, RuntimeError, WatermarkingError) as error:
            return _internal_error_response(
                "watermark application", error,
                "watermarking failed", 500,
            )

        # Use safe name components and a unique suffix to prevent overwrites.
        base_name = secure_filename(
            Path(row.name or file_path.name).stem
        )[:60] or "document"
        try:
            dest_dir = _safe_resolve_under_storage(
                file_path.parent / "watermarks", app.config["STORAGE_DIR"],
            )
            dest_dir.mkdir(parents=True, exist_ok=True)
            candidate = f"{base_name}__{intended_slug}__{uuid4().hex}.pdf"
            dest_path = _safe_resolve_under_storage(dest_dir / candidate, dest_dir)
            with dest_path.open("xb") as output:
                output.write(wm_bytes)
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "could not store watermarked file"}), 500

        # Generate an unpredictable 40-character download link.
        link_token = secrets.token_hex(20)

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("""
                        INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                    """),
                    {
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path)
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except SQLAlchemyError as error:
            # Best-effort cleanup if DB insert fails.
            try:
                _safe_resolve_under_storage(
                    dest_path, app.config["STORAGE_DIR"],
                ).unlink(missing_ok=True)
            except (OSError, ValueError) as cleanup_error:
                _log_internal_failure("watermark file cleanup", cleanup_error)
            return _internal_error_response(
                "watermark version database operation", error,
                "service temporarily unavailable", 503,
            )

        return jsonify({
            "id": vid,
            "documentid": doc_id,
            "link": link_token,
            "intended_for": intended_for,
            "method": method,
            "position": position,
            "filename": candidate,
            "size": len(wm_bytes),
        }), 201

    @app.post("/api/load-plugin")
    @require_auth
    def load_plugin():
        return jsonify({
            "error": "Loading plugin files is no longer supported"
        }), 410

    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        # Expose component methods and the combined method used by RMAP.
        method_names = (
            "davide-watermark",
            "francesco-watermark",
            "khaled-text-spacing-watermark",
            "group13-watermark",
        )
        methods = [
            {
                "name": name,
                "description": WMUtils.get_method(name).get_usage(),
            }
            for name in method_names
        ]
        return jsonify({"methods": methods, "count": len(methods)}), 200

    def _fingerprint_attribution(method, key: str, leaked_path: Path):
        """Return the best matching RMAP version, or None when no score qualifies.

        Compare the leak against the RMAP source and versions issued with the same method.
        Database errors propagate to the caller.
        """
        try:
            impl = WMUtils.get_method(method)
        except (KeyError, ValueError, TypeError):
            return None
        if not hasattr(impl, "score_recipients"):
            return None

        with get_engine().connect() as conn:
            source = conn.execute(
                text("SELECT path FROM Documents WHERE id = :id LIMIT 1"),
                {"id": app.config["RMAP_DOCUMENT_ID"]},
            ).first()
            versions = conn.execute(
                text("""
                    SELECT intended_for, link, secret
                    FROM Versions
                    WHERE documentid = :docid AND method = :method
                """),
                {"docid": app.config["RMAP_DOCUMENT_ID"], "method": impl.name},
            ).all()
        if not source or not versions:
            return None

        try:
            source_path = _safe_resolve_under_storage(
                source.path, app.config["STORAGE_DIR"],
            )
            scores = impl.score_recipients(
                pdf=str(leaked_path),
                original=str(source_path),
                key=key,
                secrets=[v.secret for v in versions],
            )
        except (ValueError, TypeError, OSError, RuntimeError, fitz.FileDataError, WatermarkingError) as error:
            _log_internal_failure("fingerprint attribution", error)
            return None

        best = max(versions, key=lambda v: scores.get(v.secret, float("-inf")))
        if scores.get(best.secret, float("-inf")) < impl.ATTRIBUTION_THRESHOLD:
            return None
        return best

    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}

        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": doc_id, "uid": int(g.user["id"])},
                ).first()
                # Only the RMAP service account (owner of RMAP_DOCUMENT_ID) gets leak
                # attribution; everyone else keeps the plain response.
                is_rmap_service = False
                if rmap_server is not None:
                    is_rmap_service = conn.execute(
                        text("""
                            SELECT 1 FROM Documents
                            WHERE id = :id AND ownerid = :uid
                            LIMIT 1
                        """),
                        {"id": app.config["RMAP_DOCUMENT_ID"], "uid": int(g.user["id"])},
                    ).first() is not None
        except SQLAlchemyError as error:
            return _internal_error_response(
                "watermark read document lookup", error,
                "service temporarily unavailable", 503,
            )

        if not row:
            return jsonify({"error": "document not found"}), 404

        try:
            file_path = _safe_resolve_under_storage(
                row.path, app.config["STORAGE_DIR"],
            )
        except (RuntimeError, ValueError, OSError):
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.is_file():
            return jsonify({"error": "file missing on disk"}), 410

        secret = None
        read_error = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except (ValueError, TypeError, OSError, RuntimeError, fitz.FileDataError, WatermarkingError) as error:
            read_error = error
        if read_error is not None and not is_rmap_service:
            return _internal_error_response(
                "watermark read", read_error,
                "could not read watermark", 400,
            )
        result = {
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }
        if is_rmap_service:
            version = None
            try:
                if secret is not None:
                    with get_engine().connect() as conn:
                        version = conn.execute(
                            text("""
                                SELECT intended_for, link
                                FROM Versions
                                WHERE documentid = :docid AND secret = :secret
                                LIMIT 1
                            """),
                            {"docid": app.config["RMAP_DOCUMENT_ID"], "secret": secret},
                        ).first()
                # The blind read failed or matched nothing: fall back to the fingerprint, for
                # methods that support informed detection.
                if version is None:
                    version = _fingerprint_attribution(method, key, file_path)
            except SQLAlchemyError as error:
                return _internal_error_response(
                    "watermark read attribution lookup", error,
                    "service temporarily unavailable", 503,
                )
            if read_error is not None and version is None:
                return _internal_error_response(
                    "watermark read", read_error,
                    "could not read watermark", 400,
                )
            result["attribution"] = (
                {"intended_for": version.intended_for, "link": version.link}
                if version else None
            )
        return jsonify(result), 201

    return app

# WSGI entrypoint.
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)  # noqa: S104 - dev server inside the container
