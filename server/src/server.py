import os
import io
import json
import uuid
import logging
import re
import hashlib
import datetime as dt
from pathlib import Path
from functools import wraps

from flask import Flask, jsonify, request, g, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError



from rmap import RMAPServer, RMAPError
from rmap.exceptions import PassphraseRequiredException, UnsupportedKeyException

import watermarking_utils as WMUtils
#from watermarking_utils import METHODS, apply_watermark, read_watermark, explore_pdf, is_watermarking_applicable, get_method


# ----------------------------------------------------------------------
# Operations log (Specialization D)
#
# Every security-relevant event is emitted as ONE JSON object per line on the
# logger named "tatou.audit". Line-delimited JSON is deliberate: it stays
# greppable with plain tools and is directly ingestible by the detection
# script, without pulling a log stack into a single-VM course project.
#
# An "event" is always one of a small fixed set, so the detection rules can be
# written against the event name instead of against free text. The set is
# derived from the observation points OP-1..OP-5 in the threat model; nothing
# is logged that the threat model did not ask for (in particular, RMAP failures
# record the *class* of failure but never the identity, which would be an
# enumeration oracle - see T-24).
# ----------------------------------------------------------------------

AUDIT_LOGGER = logging.getLogger("tatou.audit")


def _audit(event: str, level: int = logging.WARNING, **fields) -> None:
    """Emit one structured audit record.

    `fields` are written verbatim into the JSON object, so callers should only
    pass non-sensitive values: never a password, a token, a secret, a full
    private path, or an RMAP identity on a failure path.
    """
    record = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        "request_id": getattr(g, "request_id", None),
        "ip": _client_ip(),
        "method": request.method if request else None,
        "path": request.path if request else None,
    }
    record.update({k: v for k, v in fields.items() if v is not None})
    AUDIT_LOGGER.log(level, json.dumps(record, ensure_ascii=True, sort_keys=True))


def _client_ip() -> str | None:
    """Best-effort client address.

    We do not trust X-Forwarded-For: there is no reverse proxy in front of the
    server, so a forged header would let an attacker choose which address the
    log blames. The peer address is the only value that cannot be spoofed here.
    """
    try:
        return request.remote_addr
    except RuntimeError:  # outside a request context
        return None


def create_app():
    app = Flask(__name__)

    # --- Config ---
    # --- Config ---
    # Fail closed: refuse to start with a missing/weak/default signing key.
    # The token signing key must never fall back to a value that appears in the
    # source code, otherwise anyone can forge authentication tokens.
    secret_key = os.environ.get("SECRET_KEY", "")
    if len(secret_key) < 32 or secret_key == "dev-secret-change-me":
        raise RuntimeError(
            "SECRET_KEY is missing, too short (<32 chars), or set to the insecure "
            "default. Generate one with:  python -c \"import secrets; "
            "print(secrets.token_urlsafe(48))\"  and set it in .env / the environment. "
            "Refusing to start."
        )
    app.config["SECRET_KEY"] = secret_key

    app.config["STORAGE_DIR"] = Path(os.environ.get("STORAGE_DIR", "./storage")).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))
    # Cap request bodies: without a limit an authenticated client can fill the
    # disk, and the RMAP wire messages are only a few hundred bytes anyway.
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- Operations log -------------------------------------------------
    # A dedicated audit logger whose records are single-line JSON objects.
    # propagate=False keeps audit records out of the root logger, so raising
    # this logger's level never changes how the rest of Flask logs, and tweaking
    # Flask's logging never silently drops an audit record. This is what the
    # detection script consumes (one event per line).
    if not AUDIT_LOGGER.handlers:
        _handler = logging.StreamHandler()
        _handler.setFormatter(logging.Formatter("%(message)s"))
        AUDIT_LOGGER.addHandler(_handler)
        AUDIT_LOGGER.propagate = False
        AUDIT_LOGGER.setLevel(logging.INFO)

    @app.before_request
    def _assign_request_id():
        # A short id per request lets every line belonging to one request be
        # correlated even though the access log and the audit log are separate
        # streams. It is not a secret and never leaves the server.
        g.request_id = uuid.uuid4().hex[:12]

    # --- RMAP configuration (also fail closed: no keys => no service) ---
    # The RMAP endpoints let other groups authenticate against this server and
    # retrieve a watermarked copy of our confidential document. Without a
    # usable key set the protocol simply cannot work, so a misconfigured
    # deployment must fail loudly at start-up rather than silently at request
    # time (same reasoning as SECRET_KEY above).
    rmap_pub_path = Path(os.environ.get("RMAP_SERVER_PUB_PATH", "/app/keys/server_pub.asc"))
    rmap_priv_path = Path(os.environ.get("RMAP_SERVER_PRIV_PATH", "/app/keys/server_priv.asc"))
    rmap_clients_dir = Path(os.environ.get("RMAP_CLIENTS_DIR", "/app/keys/clients"))

    for _name, _path in (
        ("RMAP_SERVER_PUB_PATH", rmap_pub_path),
        ("RMAP_SERVER_PRIV_PATH", rmap_priv_path),
    ):
        if not _path.is_file():
            raise RuntimeError(
                f"{_name} does not point to an existing file: {_path}. "
                "Mount the key directory (docker compose) or set the path in .env. "
                "Refusing to start."
            )
    if not rmap_clients_dir.is_dir():
        raise RuntimeError(
            f"RMAP_CLIENTS_DIR does not point to an existing directory: {rmap_clients_dir}. "
            "Refusing to start."
        )

    # An empty value means "the private key is not passphrase protected".
    rmap_passphrase = os.environ.get("RMAP_KEY_PASSPHRASE") or None

    wm_secret_key = os.environ.get("WM_SECRET_KEY", "")
    if len(wm_secret_key) < 32:
        raise RuntimeError(
            "WM_SECRET_KEY is missing or too short (<32 chars). Generate one with:  "
            "python -c \"import secrets; print(secrets.token_urlsafe(32))\"  "
            "and set it in .env / the environment. Refusing to start."
        )

    # The confidential document that other groups retrieve through RMAP. It is
    # never served directly: every retrieval gets its own watermarked copy.
    rmap_source_pdf = Path(os.environ.get("RMAP_SOURCE_PDF", "/app/confidential.pdf"))
    if not rmap_source_pdf.is_file():
        raise RuntimeError(
            f"RMAP_SOURCE_PDF does not point to an existing file: {rmap_source_pdf}. "
            "Mount the confidential document (docker compose) or set the path in .env. "
            "Refusing to start."
        )

    # Existence alone is not enough. A file with the right name but the wrong
    # content would only surface as an unexplained 500 the first time another
    # group calls us - so validate the magic bytes at start-up instead.
    try:
        with rmap_source_pdf.open("rb") as _fh:
            _head = _fh.read(5)
    except OSError as exc:
        raise RuntimeError(f"RMAP_SOURCE_PDF cannot be read: {rmap_source_pdf} ({exc})")
    if _head != b"%PDF-":
        raise RuntimeError(
            f"RMAP_SOURCE_PDF is not a PDF (missing the %PDF- header): {rmap_source_pdf}. "
            "Check that the assigned confidential document was copied there and not "
            "some other file with a similar name. Refusing to start."
        )

    app.config["WM_SECRET_KEY"] = wm_secret_key
    app.config["RMAP_SOURCE_PDF"] = rmap_source_pdf
    # "rmc" (redundant multi-channel) is our strongest implemented method, so it
    # is the default for RMAP retrievals.
    app.config["RMAP_WM_METHOD"] = os.environ.get("RMAP_WM_METHOD", "rmc")

    # NOTE: RMAPServer keeps *mutable* per-handshake state (which nonceServer
    # belongs to which identity). It therefore must not be parked in
    # app.config - config holds static values, not live state - and it has to
    # be created per application instance so that several create_app() calls
    # (e.g. in tests) never share handshake state. A closure variable gives
    # the route handlers below direct access to it.
    rmap_server = RMAPServer(
        server_public_key_path=rmap_pub_path,
        server_private_key_path=rmap_priv_path,
        passphrase=rmap_passphrase,
        linkPrefix="",  # the API spec expects the bare 32-hex link
        verbose=False,
        logger=app.logger,
    )
    rmap_server.loadIdentities(rmap_clients_dir)
    app.logger.info("RMAP initialised: %d client identities loaded", len(rmap_server.identities))

    # Expose it on the app as well: Flask's `extensions` dict is the idiomatic
    # home for third-party objects bound to an application (what Flask-SQLAlchemy
    # does with app.extensions["sqlalchemy"]). The route handlers below use the
    # closure variable, but tests and tools can reach the same instance here.
    app.extensions["rmap"] = rmap_server
    import threading
    rmap_lock = threading.Lock()  # RMAP session state is shared between threads

    # --- DB engine only (no Table metadata) ---
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

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                _audit("auth.failure", reason="missing_header")
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(token, max_age=app.config["TOKEN_TTL_SECONDS"])
            except SignatureExpired:
                _audit("auth.failure", reason="expired")
                return _auth_error("Token expired")
            except BadSignature:
                # A token that does not verify. Could be a typo, could be an
                # attempt to forge one after the signing key changed. We record
                # the attempt and the source, never the token itself.
                _audit("auth.failure", reason="bad_signature")
                return _auth_error("Invalid token")
            g.user = {"id": int(data["uid"]), "login": data["login"], "email": data.get("email")}
            # The signature verified, so `data` is trustworthy; recording the
            # claimed uid is therefore safe and makes cross-account probing
            # visible in the log.
            g.audit_user = g.user["login"]
            return f(*args, **kwargs)
        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Routes ---
    
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
        except Exception:
            db_ok = False
        return jsonify({"message": "The server is up and running.", "db_connected": db_ok}), 200

    # POST /api/create-user {email, login, password}
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
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""
        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("SELECT id, email, login, hpassword FROM Users WHERE email = :email LIMIT 1"),
                    {"email": email},
                ).first()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        if not row or not check_password_hash(row.hpassword, password):
            # The password itself is never logged, and the supplied email is
            # logged as given (not as stored) so that enumeration attempts are
            # visible even when no such account exists. This is the only signal
            # a password-spraying campaign leaves: see threat T-10 in the threat
            # model. We deliberately do NOT log whether the account existed.
            _audit("login.failure", email=email[:320])
            return jsonify({"error": "invalid credentials"}), 401

        _audit("login.success", level=logging.INFO, uid=int(row.id), login=row.login)
        token = _serializer().dumps({"uid": int(row.id), "login": row.login, "email": row.email})
        return jsonify({"token": token, "token_type": "bearer", "expires_in": app.config["TOKEN_TTL_SECONDS"]}), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            _audit("upload.rejected", reason="no_file_part")
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            _audit("upload.rejected", reason="empty_filename")
            return jsonify({"error": "empty filename"}), 400

        # The client-supplied name ends up in a filesystem path, so it must
        # never be trusted as-is: "../../plugins/evil.pkl" would otherwise
        # escape the user's directory. secure_filename strips directories and
        # unsafe characters.
        raw_filename = file.filename
        fname = secure_filename(file.filename)
        if not fname:
            # secure_filename returned nothing, which means the supplied name had
            # no usable characters at all - a strong sign of a traversal or
            # injection attempt rather than a mistake. Record the raw name.
            _audit("upload.rejected", reason="path_traversal_or_unsafe_name",
                   raw_filename=raw_filename[:255])
            return jsonify({"error": "invalid filename"}), 400
        if fname != raw_filename:
            # Documented, not blocked: normalisation changed the name, so an
            # attempt to smuggle a path separator is visible in the log while
            # the upload still proceeds with the safe name.
            _audit("upload.normalised", raw_filename=raw_filename[:255], stored_as=fname[:255])

        # The API specification says only PDFs may be uploaded, so check the
        # actual content instead of trusting the extension.
        head = file.stream.read(5)
        file.stream.seek(0)
        if head != b"%PDF-":
            _audit("upload.rejected", reason="not_a_pdf", raw_filename=raw_filename[:255])
            return jsonify({"error": "only PDF files are accepted"}), 400

        user_dir = app.config["STORAGE_DIR"] / "files" / secure_filename(g.user["login"])
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%S%fZ")
        final_name = (request.form.get("name") or fname)[:255]
        stored_name = f"{ts}__{fname}"
        stored_path = user_dir / stored_name
        file.save(stored_path)

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

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
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        return jsonify({
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat() if hasattr(row.creation, "isoformat") else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }), 201

    # GET /api/list-documents
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
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        docs = [{
            "id": int(r.id),
            "name": r.name,
            "creation": r.creation.isoformat() if hasattr(r.creation, "isoformat") else str(r.creation),
            "sha256": r.sha256_hex,
            "size": int(r.size),
        } for r in rows]
        return jsonify({"documents": docs}), 200



    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
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
                        WHERE u.login = :glogin AND d.id = :did
                    """),
                    {"glogin": str(g.user["login"]), "did": document_id},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "secret": r.secret,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    
    # GET /api/list-all-versions
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
                        WHERE u.login = :glogin
                    """),
                    {"glogin": str(g.user["login"])},
                ).all()
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        versions = [{
            "id": int(r.id),
            "documentid": int(r.documentid),
            "link": r.link,
            "intended_for": r.intended_for,
            "method": r.method,
        } for r in rows]
        return jsonify({"versions": versions}), 200
    
    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
    
        # Support both path param and ?id=/ ?documentid=
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
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.name if row.name.lower().endswith(".pdf") else f"{row.name}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )
        # Strong validator
        if isinstance(row.sha256_hex, str) and row.sha256_hex:
            resp.set_etag(row.sha256_hex.lower())

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        return resp
    
    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
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
        except Exception as e:
            return jsonify({"error": f"database error: {str(e)}"}), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            file_path.resolve().relative_to(app.config["STORAGE_DIR"].resolve())
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # Serve inline with caching hints + ETag based on stored sha256
        resp = send_file(
            file_path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf",
            conditional=True,   # enables 304 if If-Modified-Since/Range handling
            max_age=0,
            last_modified=file_path.stat().st_mtime,
        )

        resp.headers["Cache-Control"] = "private, max-age=0"
        return resp
    
    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        return fp

    # --- RMAP helpers ---

    def _rmap_document_id(conn, sha_hex: str, size: int) -> int:
        """Return the Documents row for the confidential source PDF, creating it on first use.

        Versions.documentid is a NOT NULL foreign key, so every watermarked copy
        we hand out has to hang off a Documents row. The source document is
        owned by a synthetic, unusable account ("tatou-rmap") so that no real
        user can list, read or delete it.
        """
        source = app.config["RMAP_SOURCE_PDF"]
        row = conn.execute(
            text("SELECT id FROM Documents WHERE path = :p LIMIT 1"),
            {"p": str(source)},
        ).first()
        if row:
            return int(row.id)

        owner = conn.execute(
            text("SELECT id FROM Users WHERE login = :l LIMIT 1"),
            {"l": "tatou-rmap"},
        ).first()
        if owner:
            owner_id = int(owner.id)
        else:
            # "!" is not a valid password hash, so this account can never be
            # logged into - it exists only as the owner of the source document.
            res = conn.execute(
                text("INSERT INTO Users (email, hpassword, login) VALUES (:e, :h, :l)"),
                {"e": "rmap@tatou.local", "h": "!", "l": "tatou-rmap"},
            )
            owner_id = int(res.lastrowid)

        res = conn.execute(
            text("""
                INSERT INTO Documents (name, path, ownerid, sha256, size)
                VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
            """),
            {
                "name": source.name,
                "path": str(source),
                "ownerid": owner_id,
                "sha256hex": sha_hex,
                "size": int(size),
            },
        )
        return int(res.lastrowid)

    def _create_rmap_version(identity: str, link: str) -> None:
        """Produce the watermarked copy for `identity` and record it in the database.

        The specification is explicit: a link must never leave the server unless
        the per-identity watermarked copy has actually been created and recorded.
        """
        source = app.config["RMAP_SOURCE_PDF"]
        method = app.config["RMAP_WM_METHOD"]
        key = app.config["WM_SECRET_KEY"]
        # Includes the handshake link, so every retrieval is individually
        # watermarked and a leaked copy can be traced to one specific handshake.
        secret = f"{identity}:{link}"

        wm_bytes = WMUtils.apply_watermark(
            pdf=str(source), secret=secret, key=key, method=method, position=None
        )
        if not wm_bytes:
            raise RuntimeError("watermarking produced no output")

        dest_dir = app.config["STORAGE_DIR"] / "rmap" / secure_filename(identity)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / f"{link}.pdf"
        dest_path.write_bytes(wm_bytes)

        with get_engine().begin() as conn:
            documentid = _rmap_document_id(
                conn, sha_hex=_sha256_file(dest_path), size=dest_path.stat().st_size
            )
            conn.execute(
                text("""
                    INSERT INTO Versions (documentid, link, intended_for, secret, method, position, path)
                    VALUES (:documentid, :link, :intended_for, :secret, :method, :position, :path)
                """),
                {
                    "documentid": documentid,
                    "link": link,
                    "intended_for": identity,
                    "secret": secret,
                    "method": method,
                    "position": "",
                    "path": str(dest_path),
                },
            )

    # DELETE /api/delete-document  (and variants)
    @app.route("/api/delete-document", methods=["DELETE", "POST"])  # POST supported for convenience
    @app.route("/api/delete-document/<int:document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if document_id is None:
            raw_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
            try:
                document_id = int(raw_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        # Fetch the document, enforcing ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("delete_document: lookup failed")
            return jsonify({"error": "database error"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception:
                    app.logger.exception("delete_document: failed to delete file for doc id=%s", row.id)
            else:
                file_missing = True
        except RuntimeError:
            # Path escapes storage root; refuse to touch the file
            app.logger.error("delete_document: path safety check failed for doc id=%s", row.id)

        # Delete DB row (cascades to Versions via ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :uid"),
                    {"id": document_id, "uid": int(g.user["id"])},
                )
        except Exception:
            app.logger.exception("delete_document: delete failed")
            return jsonify({"error": "database error during delete"}), 503

        _audit("document.deleted", level=logging.INFO, uid=int(g.user["id"]),
               login=g.user["login"], documentid=document_id, file_deleted=file_deleted)
        return jsonify({
            "deleted": True,
            "id": document_id,
            "file_deleted": file_deleted,
            "file_missing": file_missing,
        }), 200

        
        
    # POST /api/create-watermark or /api/create-watermark/<id>  → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        elif not isinstance(payload, dict):
            return jsonify({"error": "JSON body must be an object"}), 400
        # Accept document ID from URL path, query parameters, or JSON body.
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or payload.get("id")
            )
        doc_id = document_id
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not intended_for or not isinstance(secret, str) or not isinstance(key, str):
            return jsonify({"error": "method, intended_for, secret, and key are required"}), 400

        # Look up the document, enforcing ownership: only the owner may create
        # watermarked versions of their documents.
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
        except Exception:
            app.logger.exception("create_watermark: document lookup failed")
            return jsonify({"error": "database error"}), 503

        if not row:
            # Same answer whether the document does not exist or belongs to
            # somebody else - no document-enumeration oracle.
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method,
                pdf=str(file_path),
                position=position
            )
            if applicable is False:
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            return jsonify({"error": f"watermark applicability check failed: {e}"}), 400

        # apply watermark → bytes
        try:
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=position
            )
            if not isinstance(wm_bytes, (bytes, bytearray)) or len(wm_bytes) == 0:
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            return jsonify({"error": f"watermarking failed: {e}"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            return jsonify({"error": f"failed to write watermarked file: {e}"}), 500

        # link token = sha1(watermarked_file_name)
        link_token = hashlib.sha1(candidate.encode("utf-8")).hexdigest()

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
                        "path": dest_path
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception as e:
            # best-effort cleanup if DB insert fails
            try:
                dest_path.unlink(missing_ok=True)
            except Exception:
                pass
            return jsonify({"error": f"database error during version insert: {e}"}), 503

        _audit("watermark.created", level=logging.INFO, uid=int(g.user["id"]),
               login=g.user["login"], documentid=doc_id, method=method,
               intended_for=intended_for, version_id=vid)
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
        
        
    
    
    # GET /api/get-watermarking-methods -> {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append({"name": m, "description": WMUtils.get_method(m).get_usage()})
            
        return jsonify({"methods": methods, "count": len(methods)}), 200
        
    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
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
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            doc_id = int(doc_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # Look up the document, enforcing ownership. Reading a watermark
        # recovers the secret that identifies the recipient, so this must never
        # work across accounts.
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
        except Exception:
            app.logger.exception("read_watermark: document lookup failed")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410
        
        secret = None
        try:
            secret = WMUtils.read_watermark(
                method=method,
                pdf=str(file_path),
                key=key
            )
        except Exception as e:
            return jsonify({"error": f"Error when attempting to read watermark: {e}"}), 400
        _audit("watermark.read", level=logging.INFO, uid=int(g.user["id"]),
               login=g.user["login"], documentid=doc_id, method=method)
        return jsonify({
            "documentid": doc_id,
            "secret": secret,
            "method": method,
            "position": position
        }), 201

    # POST /api/identify-document/<int:document_id>  (multipart/form-data)
    #
    # Given a PDF found "in the wild", tells the owner of `document_id` which
    # of their own watermarked versions it matches, without forcing them to
    # re-upload the file as if it were new content to watermark.
    #
    # Security posture (see API.md#identify-document for the full list):
    #   - requires authentication, and is scoped to the caller's own document
    #     (same not-found-vs-not-owned ambiguity as read-watermark/get-document);
    #   - validates the method name against the registry *before* touching the
    #     uploaded bytes or the key, answering 405 for an unknown method;
    #   - validates the upload is really a PDF by content, not by filename;
    #   - never writes the uploaded bytes to disk - everything happens in
    #     memory, so this route cannot be used to plant files or fill the disk;
    #   - never echoes the key, the computed secret of a failed attempt, or any
    #     filesystem path back in an error message;
    #   - the matches it returns are restricted to the same document and the
    #     same method, and only ever expose {versionid, intended_for}.
    @app.post("/api/identify-document/<int:document_id>")
    @require_auth
    def identify_document(document_id: int):
        # --- parameters (multipart/form-data, per the fixed API contract) ---
        method = request.form.get("method")
        key = request.form.get("key")
        position = request.form.get("position") or None

        if not method or not isinstance(method, str):
            return jsonify({"error": "method is required"}), 400
        if not key or not isinstance(key, str):
            return jsonify({"error": "key is required"}), 400

        # Unknown method is checked first, and before the file is even read:
        # a caller probing for valid method names must not learn anything
        # about a document's existence, and the uploaded bytes are never
        # processed by code we have no watermarking implementation for.
        if method not in WMUtils.METHODS:
            return jsonify({"error": "unknown watermarking method"}), 405

        if "file" not in request.files:
            return jsonify({"error": "file is required (multipart/form-data)"}), 400
        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        # Check the actual content, not the filename/extension - a renamed
        # non-PDF must not reach the watermark reader.
        head = file.stream.read(5)
        file.stream.seek(0)
        if head != b"%PDF-":
            return jsonify({"error": "only PDF files are accepted"}), 400

        # The upload is processed entirely in memory: it is never written
        # under STORAGE_DIR, so this route cannot be used to plant a file on
        # the server or to exhaust disk space with "leaked" documents that
        # are, in fact, attacker-controlled content.
        pdf_bytes = file.stream.read()

        # Ownership check. Same answer (404) whether document_id does not
        # exist or belongs to another user - no document-enumeration oracle,
        # exactly as for read-watermark and get-document.
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text("""
                        SELECT id
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception:
            app.logger.exception("identify_document: document lookup failed")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # Recover the secret from the uploaded file. Every failure here
        # (wrong key, no watermark of this method present, corrupt payload)
        # is reported generically: the underlying exceptions never include
        # the key or a filesystem path (see watermarking_method.py), but we
        # still keep the message generic on purpose so repeated guesses give
        # an attacker no finer-grained signal than "it failed".
        try:
            secret = WMUtils.read_watermark(method=method, pdf=pdf_bytes, key=key)
        except Exception:
            return jsonify({"error": "unable to read a watermark from this file with the given method and key"}), 400

        # Only versions of *this* document, created with *this* method, and
        # whose stored secret matches the one just read, are reported. The
        # response exposes nothing beyond {versionid, intended_for} - never
        # another version's secret, key, or storage path.
        try:
            with get_engine().connect() as conn:
                matches = conn.execute(
                    text("""
                        SELECT id, intended_for
                        FROM Versions
                        WHERE documentid = :documentid AND method = :method AND secret = :secret
                    """),
                    {"documentid": document_id, "method": method, "secret": secret},
                ).fetchall()
        except Exception:
            app.logger.exception("identify_document: version lookup failed")
            return jsonify({"error": "database error"}), 503

        _audit("document.identified", level=logging.INFO, uid=int(g.user["id"]),
               login=g.user["login"], documentid=document_id, method=method,
               match_count=len(matches))

        return jsonify({
            "documentid": document_id,
            "method": method,
            "secret": secret,
            "matches": [
                {"versionid": int(m.id), "intended_for": m.intended_for} for m in matches
            ],
        }), 200

    # ------------------------------------------------------------------
    # RMAP endpoints
    #
    # Other groups authenticate against this server with the RMAP protocol
    # (a 4-message PGP handshake) and, in return, receive a link to a copy of
    # our confidential document watermarked specifically for them. Neither
    # endpoint uses a bearer token: the caller proves who it is through its
    # ability to decrypt a value that only its private key could have produced.
    # All protocol cryptography is handled by the `rmap` library; we only
    # provide the HTTP shell, the error mapping and the watermarking.
    # ------------------------------------------------------------------

    # POST /api/rmap-initiate  →  RMAP message 1 in, response 1 out
    @app.post("/api/rmap-initiate")
    def rmap_initiate():
        msg1 = request.get_json(silent=True)
        try:
            with rmap_lock:
                _identity, resp1 = rmap_server.receiveMsg1(msg1)
        except (UnsupportedKeyException, PassphraseRequiredException):
            # Our *own* key material is unusable. That is a server-side
            # misconfiguration, not something the caller did wrong.
            app.logger.exception("RMAP initiate: server key material is unusable")
            return jsonify({"error": "server configuration error"}), 500
        except RMAPError as exc:
            # One generic answer for every client-side failure, on purpose.
            # Reporting "unknown identity" separately from "cannot decrypt"
            # would let an attacker enumerate which groups are known to us.
            _audit("rmap.initiate.rejected", reason="protocol_error")
            app.logger.warning("RMAP initiate rejected: %s", exc)
            return jsonify({"error": "invalid request"}), 400
        except Exception:
            # rmap 2.0.0 still indexes the decrypted JSON directly (data["identity"]),
            # so a validly encrypted message with missing or oddly typed fields
            # raises KeyError/TypeError instead of RMAPError. That is a bad request.
            _audit("rmap.initiate.rejected", reason="unexpected_payload")
            app.logger.warning("RMAP initiate: unexpected payload", exc_info=True)
            return jsonify({"error": "invalid request"}), 400
        return jsonify(resp1), 200

    # POST /api/rmap-get-link  →  RMAP message 2 in, response 2 (the link) out
    @app.post("/api/rmap-get-link")
    def rmap_get_link():
        msg2 = request.get_json(silent=True)
        try:
            with rmap_lock:
                identity, expected_link, resp2 = rmap_server.receiveMsg2(msg2)
                # One-shot session: invalidate it now so a replayed message 2
                # is rejected up front (no second watermarking run, no overwrite).
                _info = rmap_server.identities[identity]
                rmap_server._nonce_server_index.pop(_info.nonceServer, None)
                _info.nonceClient = None
                _info.nonceServer = None
        except (UnsupportedKeyException, PassphraseRequiredException):
            app.logger.exception("RMAP get-link: server key material is unusable")
            return jsonify({"error": "server configuration error"}), 500
        except RMAPError as exc:
            _audit("rmap.getlink.rejected", reason="protocol_error")
            app.logger.warning("RMAP get-link rejected: %s", exc)
            return jsonify({"error": "invalid request"}), 400
        except Exception:
            # The library promises RMAPError for protocol failures, but a
            # decryptable body missing the expected key can still surface as
            # KeyError/TypeError. Treat that as a bad request, not a 500.
            _audit("rmap.getlink.rejected", reason="unexpected_payload")
            app.logger.warning("RMAP get-link: unexpected payload", exc_info=True)
            return jsonify({"error": "invalid request"}), 400

        # The spec says the link is exactly hex(nonceClient) || hex(nonceServer),
        # 32 hex characters. A client can send an out-of-range nonceClient in
        # message 1, which would give a different shape: refuse it here, before
        # a file is written or a row is inserted.
        if not re.fullmatch(r"[0-9a-f]{32}", expected_link):
            _audit("rmap.getlink.rejected", reason="bad_link_format")
            app.logger.warning("RMAP get-link: link is not 32 lowercase hex characters")
            return jsonify({"error": "invalid request"}), 400

        # A link must never be returned unless the watermarked copy exists and
        # has been recorded, so this completes *before* we answer.
        try:
            _create_rmap_version(identity=identity, link=expected_link)
        except Exception:
            app.logger.exception("RMAP get-link: could not produce/record the watermarked copy")
            return jsonify({"error": "server error"}), 500

        return jsonify(resp2), 200

    # ------------------------------------------------------------------
    # Related problem found while building identify-document:
    # MAX_CONTENT_LENGTH was already enforced (20 MiB default) for every
    # route, but Werkzeug's default handling of the resulting
    # RequestEntityTooLarge answers with an HTML error page, not the
    # {"error": <string>} JSON object every other failure in this API
    # returns. identify-document is the first route whose whole point is to
    # accept an arbitrary, possibly oversized, uploaded file, so this becomes
    # directly relevant here: without this handler, a too-large upload would
    # leak an HTML body where every client of this API expects JSON.
    # ------------------------------------------------------------------
    @app.errorhandler(413)
    def _request_too_large(_exc):
        return jsonify({"error": "request body too large"}), 413

    return app
    

# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

