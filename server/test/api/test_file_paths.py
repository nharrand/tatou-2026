import hashlib
import io
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import fitz
import pytest
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import BadRequest, InternalServerError

pytestmark = pytest.mark.usefixtures("toy_eof_method")


def make_pdf(*, encrypted=False):
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Tatou upload validation fixture")
    options = {}
    if encrypted:
        options = {
            "encryption": fitz.PDF_ENCRYPT_AES_256,
            "owner_pw": "owner-password",
            "user_pw": "user-password",
        }
    data = document.tobytes(**options)
    document.close()
    return data


def make_empty_pdf():
    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n",
    ]
    parts = [b"%PDF-1.4\n"]
    offsets = []
    for item in objects:
        offsets.append(sum(map(len, parts)))
        parts.append(item)
    xref_offset = sum(map(len, parts))
    parts.extend([
        b"xref\n0 3\n0000000000 65535 f \n",
        b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets),
        f"trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(),
    ])
    return b"".join(parts)

PDF = make_pdf()
WATERMARK = {"method": "toy-eof", "intended_for": "reader", "secret": "secret", "key": "key"}
SENSITIVE_CANARY = "sensitive=/app/flag;key=do-not-log;sql=SELECT-secret"
OPERATIONS = [
    ("GET", "/api/get-document/42", {}),
    ("GET", "/api/get-version/shared", {}),
    ("POST", "/api/create-watermark/42", {"json": WATERMARK}),
    ("POST", "/api/read-watermark/42", {"json": WATERMARK}),
    ("DELETE", "/api/delete-document/42", {}),
]


@pytest.fixture
def file_app(tmp_path, monkeypatch):
    storage = tmp_path / "storage"
    monkeypatch.setenv("STORAGE_DIR", str(storage))
    monkeypatch.setenv("SECRET_KEY", "file-path-test-key")
    import server

    app = server.create_app()
    engine = create_engine("sqlite://")

    # Support the small number of MySQL functions used by these endpoints.
    @event.listens_for(engine, "connect")
    def mysql_functions(connection, _record):
        connection.create_function("UNHEX", 1, bytes.fromhex)
        connection.create_function(
            "LAST_INSERT_ID", 0,
            lambda: connection.execute("SELECT last_insert_rowid()").fetchone()[0],
        )

    original = storage / "legacy-login" / "original.pdf"
    original.parent.mkdir()
    original.write_bytes(PDF)
    outside = tmp_path / "outside.pdf"
    outside.write_bytes(b"outside sentinel")
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE Documents (
                id INTEGER PRIMARY KEY, name TEXT, path TEXT, ownerid INTEGER,
                sha256 BLOB, size INTEGER, creation TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """))
        conn.execute(text("""
            CREATE TABLE Versions (
                id INTEGER PRIMARY KEY, documentid INTEGER, link TEXT,
                intended_for TEXT, secret TEXT, method TEXT, position TEXT, path TEXT
            )
        """))
        conn.execute(text("""
            INSERT INTO Documents (id, name, path, ownerid, sha256, size)
            VALUES (42, 'original.pdf', :path, 7, :sha, :size)
        """), {"path": str(original), "sha": hashlib.sha256(PDF).digest(), "size": len(PDF)})
        conn.execute(text("""
            INSERT INTO Versions (id, documentid, link, path)
            VALUES (1, 42, 'shared', :path)
        """), {"path": str(original)})
    app.config.update(TESTING=True, _ENGINE=engine)
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def headers(login="alice", uid=7):
        token = serializer.dumps({"uid": uid, "login": login})
        return {
            "Authorization": f"Bearer {token}",
            "X-CSRF-Protection": "1",
        }

    yield SimpleNamespace(
        app=app, client=app.test_client(), engine=engine, storage=storage, original=original,
        outside=outside, headers=headers, server=server,
    )
    engine.dispose()


def set_paths(env, value):
    with env.engine.begin() as conn:
        conn.execute(text("UPDATE Documents SET path = :path WHERE id = 42"), {"path": value})
        conn.execute(text("UPDATE Versions SET path = :path WHERE id = 1"), {"path": value})


def document_path(env, document_id):
    with env.engine.connect() as conn:
        return Path(conn.execute(
            text("SELECT path FROM Documents WHERE id = :id"), {"id": document_id}
        ).scalar_one())


def upload(env, filename="report.pdf", content=PDF, login="alice"):
    return env.client.post(
        "/api/upload-document", headers=env.headers(login),
        data={"file": (io.BytesIO(content), filename)},
    )


@pytest.fixture(params=[None, 17], ids=["normal-reads", "short-reads"])
def upload_reads(file_app, monkeypatch, request):
    """Exercise incremental streams without specifying the server's chunk size."""
    if request.param is not None:
        read_size = request.param

        class ShortReads(io.BytesIO):
            def read(self, size=-1):
                assert isinstance(size, int) and size > 0, "Upload reads must be bounded"
                return super().read(min(size, read_size))

        monkeypatch.setattr(
            file_app.app.request_class, "_get_file_stream", lambda *_args, **_kwargs: ShortReads(),
        )


def assert_sanitized_failure(response, caplog, status, message):
    assert response.status_code == status
    assert response.get_json() == {"error": message}
    assert SENSITIVE_CANARY not in response.get_data(as_text=True)
    assert SENSITIVE_CANARY not in caplog.text
    assert "Traceback" not in caplog.text


def make_symlink(link, target):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as error:
        if os.name != "nt" or not target.is_dir():
            pytest.skip(f"Symlink creation unavailable: {error}")
        # Windows junctions exercise directory redirects without symlink privileges.
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             (
                 "$ErrorActionPreference = 'Stop'; "
                 "New-Item -ItemType Junction -Path $env:TATOU_TEST_LINK "
                 "-Target $env:TATOU_TEST_TARGET | Out-Null"
             )],
            env={**os.environ, "TATOU_TEST_LINK": str(link), "TATOU_TEST_TARGET": str(target)},
            check=True, capture_output=True, text=True,
        )


@pytest.mark.parametrize("method,url,kwargs", OPERATIONS)
@pytest.mark.parametrize("path_kind", ["absolute", "traversal", "prefix", "empty", "null", "root"])
def test_invalid_stored_paths_block_all_operations(file_app, monkeypatch, method, url, kwargs, path_kind):
    env = file_app
    paths = {
        "absolute": str(env.outside), "traversal": "../outside.pdf",
        "prefix": str(env.storage.parent / "storage-other" / "outside.pdf"),
        "empty": "", "null": "bad\x00.pdf", "root": str(env.storage),
    }
    set_paths(env, paths[path_kind])
    spies = []
    for name in ["is_watermarking_applicable", "apply_watermark", "read_watermark"]:
        spy = Mock(side_effect=AssertionError("Watermark code must not run"))
        monkeypatch.setattr(env.server.WMUtils, name, spy)
        spies.append(spy)
    response = env.client.open(url, method=method, headers=env.headers(), **kwargs)
    assert response.status_code == 500, response.get_json()
    assert env.outside.read_bytes() == b"outside sentinel"
    assert env.original.read_bytes() == PDF
    with env.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == 1
        assert conn.execute(text("SELECT COUNT(*) FROM Versions")).scalar_one() == 1
    for spy in spies:
        spy.assert_not_called()


@pytest.mark.parametrize("method,url,kwargs", OPERATIONS)
def test_symlink_to_outside_file_is_rejected(file_app, method, url, kwargs):
    env = file_app
    link = env.storage / "escape"
    make_symlink(link, env.outside.parent)
    set_paths(env, str(link / env.outside.name))
    response = env.client.open(url, method=method, headers=env.headers(), **kwargs)
    assert response.status_code == 500
    assert env.outside.read_bytes() == b"outside sentinel"


@pytest.mark.parametrize("filename,login", [
    ("report.pdf", "alice"), ("../../outside.pdf", "../../escape"),
    (r"..\..\outside.pdf", r"..\..\escape"), ("/tmp/outside.pdf", "/tmp/escape"),
])
def test_upload_uses_numeric_owner_and_generated_name(file_app, filename, login):
    env = file_app
    response = upload(env, filename=filename, login=login)
    assert response.status_code == 201, response.get_json()
    path = document_path(env, response.get_json()["id"])
    assert path.parent == env.storage / "files" / "7"
    assert len(path.stem) == 32
    assert path.read_bytes() == PDF
    assert not any(item.name.startswith(".upload-") for item in path.parent.iterdir())
    assert env.outside.read_bytes() == b"outside sentinel"


def test_empty_sanitized_filename_is_rejected(file_app):
    response = upload(file_app, filename="..")
    assert response.status_code == 400
    assert response.get_json() == {"error": "lowercase .pdf extension required"}
    assert not (file_app.storage / "files").exists()


@pytest.mark.parametrize("filename", [
    "document.PDF", "document.Pdf", "document", ".pdf",
    "document.pdf.exe", "document.pdf.txt", "document.exe.pdf",
    "document.pdf.pdf",
])
def test_upload_requires_exact_lowercase_pdf_extension(file_app, filename):
    response = upload(file_app, filename=filename)
    assert response.status_code == 400
    assert response.get_json() == {"error": "lowercase .pdf extension required"}
    assert not (file_app.storage / "files").exists()


@pytest.mark.parametrize("content", [
    b"cos\n(S'payload)\nsystem\n.",
    b"<html><body>not a PDF</body></html>",
    b"",
    b"%PDF-",
    b"%PDF-1.7\nmalformed",
    make_empty_pdf(),
    make_pdf(encrypted=True),
])
def test_upload_rejects_invalid_pdf_content_without_residue(file_app, content):
    response = upload(file_app, filename="payload.pdf", content=content)
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid PDF document"}
    user_dir = file_app.storage / "files" / "7"
    assert not user_dir.exists() or list(user_dir.iterdir()) == []
    with file_app.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == 1


def test_upload_rejects_document_over_configured_size(file_app, upload_reads):
    file_app.app.config["MAX_UPLOAD_SIZE_BYTES"] = len(PDF) - 1

    response = upload(file_app)

    assert response.status_code == 413
    assert response.get_json() == {"error": "document exceeds maximum upload size"}
    user_dir = file_app.storage / "files" / "7"
    assert not user_dir.exists() or list(user_dir.iterdir()) == []
    with file_app.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == 1


@pytest.fixture
def bounded_hash_reads(file_app, monkeypatch):
    """Simulate partial file reads while rejecting whole-file memory allocations."""
    real_open = Path.open

    class PartialReader:
        def __init__(self, source):
            self.source = source

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.source.close()

        def read(self, size=-1):
            assert isinstance(size, int) and size > 0, "File reads must be bounded"
            return self.source.read(min(size, 17))

    def open_file(path, mode="r", *args, **kwargs):
        source = real_open(path, mode, *args, **kwargs)
        if mode == "rb" and path.name.startswith(".upload-") and path.is_relative_to(file_app.storage):
            return PartialReader(source)
        return source

    monkeypatch.setattr(Path, "open", open_file)


@pytest.mark.parametrize("spare_bytes", [0, 1], ids=["exact-limit", "below-limit"])
def test_upload_within_limit_preserves_content_and_metadata(
    file_app, upload_reads, bounded_hash_reads, spare_bytes,
):
    file_app.app.config["MAX_UPLOAD_SIZE_BYTES"] = len(PDF) + spare_bytes

    response = upload(file_app)

    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body["size"] == len(PDF)
    assert body["sha256"].lower() == hashlib.sha256(PDF).hexdigest()
    path = document_path(file_app, body["id"])
    assert path.read_bytes() == PDF
    assert list(path.parent.iterdir()) == [path]
    with file_app.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == 2


def test_rejected_upload_with_failed_cleanup_is_sanitized(file_app, monkeypatch, caplog):
    file_app.app.config["MAX_UPLOAD_SIZE_BYTES"] = len(PDF) - 1
    real_unlink = Path.unlink

    def deny_temporary_cleanup(path, *args, **kwargs):
        if path.name.startswith(".upload-"):
            raise PermissionError(SENSITIVE_CANARY)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_temporary_cleanup)

    response = upload(file_app)

    assert_sanitized_failure(response, caplog, 413, "document exceeds maximum upload size")
    assert "WARNING" in caplog.text
    remaining = list((file_app.storage / "files" / "7").iterdir())
    assert len(remaining) == 1
    assert remaining[0].name.startswith(".upload-")
    assert str(remaining[0]) not in caplog.text
    with file_app.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == 1


@pytest.mark.parametrize(
    "unreadable_pages,status,document_count", [({0}, 201, 2), ({0, 1}, 400, 1)],
    ids=["later-page-usable", "all-pages-unreadable"],
)
def test_upload_requires_at_least_one_loadable_page(
    file_app, monkeypatch, unreadable_pages, status, document_count,
):
    with fitz.open() as doc:
        doc.new_page()
        doc.new_page()
        data = doc.tobytes()
    real_open = fitz.open

    class DocumentWithUnreadablePages:
        def __init__(self, *args, **kwargs):
            self.document = real_open(*args, **kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.document.close()

        def __getattr__(self, name):
            return getattr(self.document, name)

        def load_page(self, index):
            page = self.document.load_page(index)
            if page.number in unreadable_pages:
                raise RuntimeError(SENSITIVE_CANARY)
            return page

    monkeypatch.setattr(file_app.server.fitz, "open", DocumentWithUnreadablePages)

    response = upload(file_app, content=data)

    assert response.status_code == status
    assert SENSITIVE_CANARY not in response.get_data(as_text=True)
    with file_app.engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM Documents")).scalar_one() == document_count


def test_upload_rejects_oversized_request_before_pdf_processing(
    file_app, monkeypatch,
):
    file_app.app.config["MAX_UPLOAD_SIZE_BYTES"] = 1024
    monkeypatch.setattr(file_app.server, "MULTIPART_OVERHEAD_BYTES", 128)
    pdf_validator = Mock(side_effect=AssertionError("PDF validation must not run"))
    monkeypatch.setattr(file_app.server, "fitz", pdf_validator)

    response = upload(file_app, content=b"%PDF-" + b"x" * 2048)

    assert response.status_code == 413
    assert response.get_json() == {"error": "document exceeds maximum upload size"}
    pdf_validator.assert_not_called()
    assert not (file_app.storage / "files").exists()


def test_upload_removes_published_file_when_database_insert_fails(file_app, caplog):
    failing_engine = Mock()
    failing_engine.begin.side_effect = SQLAlchemyError(SENSITIVE_CANARY)
    file_app.app.config["_ENGINE"] = failing_engine

    response = upload(file_app)

    assert_sanitized_failure(
        response, caplog, 503, "service temporarily unavailable",
    )
    user_dir = file_app.storage / "files" / "7"
    assert user_dir.is_dir()
    assert list(user_dir.iterdir()) == []


@pytest.mark.parametrize("method,url,payload", [
    ("POST", "/api/create-user", "user"),
    ("POST", "/api/login", "login"),
    ("GET", "/api/list-documents", None),
    ("GET", "/api/list-versions/42", None),
    ("GET", "/api/list-all-versions", None),
    ("GET", "/api/get-document/42", None),
    ("GET", "/api/get-version/shared", None),
    ("DELETE", "/api/delete-document/42", None),
    ("POST", "/api/create-watermark/42", "create-watermark"),
    ("POST", "/api/read-watermark/42", "read-watermark"),
])
def test_database_errors_are_sanitized(
    file_app, caplog, method, url, payload,
):
    failing_engine = Mock()
    failure = SQLAlchemyError(SENSITIVE_CANARY)
    failing_engine.connect.side_effect = failure
    failing_engine.begin.side_effect = failure
    file_app.app.config["_ENGINE"] = failing_engine
    kwargs = {}
    if payload == "user":
        kwargs["json"] = {
            "email": "canary@example.test", "login": "canary",
            "password": "password",
        }
    elif payload == "login":
        kwargs["json"] = {
            "email": "canary@example.test", "password": "password",
        }
    elif payload == "create-watermark":
        kwargs["json"] = WATERMARK
    elif payload == "read-watermark":
        kwargs["json"] = {"method": "toy-eof", "key": "key"}

    response = file_app.client.open(
        url, method=method, headers=file_app.headers(), **kwargs,
    )

    assert_sanitized_failure(
        response, caplog, 503, "service temporarily unavailable",
    )


def test_delete_database_error_is_sanitized_after_lookup(file_app, caplog):
    engine = SimpleNamespace(
        connect=file_app.engine.connect,
        begin=Mock(side_effect=SQLAlchemyError(SENSITIVE_CANARY)),
    )
    file_app.app.config["_ENGINE"] = engine

    response = file_app.client.delete(
        "/api/delete-document/42", headers=file_app.headers(),
    )

    assert_sanitized_failure(
        response, caplog, 503, "service temporarily unavailable",
    )
    assert not file_app.original.exists()
    with file_app.engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM Documents WHERE id = 42")
        ).scalar_one() == 1


def test_version_insert_error_is_sanitized_and_removes_output(file_app, caplog):
    engine = SimpleNamespace(
        connect=file_app.engine.connect,
        begin=Mock(side_effect=SQLAlchemyError(SENSITIVE_CANARY)),
    )
    file_app.app.config["_ENGINE"] = engine

    response = file_app.client.post(
        "/api/create-watermark/42", headers=file_app.headers(), json=WATERMARK,
    )

    assert_sanitized_failure(
        response, caplog, 503, "service temporarily unavailable",
    )
    output_dir = file_app.original.parent / "watermarks"
    assert output_dir.is_dir()
    assert list(output_dir.iterdir()) == []


@pytest.mark.parametrize("failure_kind,status,message", [
    ("applicability", 400, "invalid watermarking request"),
    ("application", 500, "watermarking failed"),
    ("read", 400, "could not read watermark"),
])
def test_watermark_exceptions_are_sanitized(
    file_app, monkeypatch, caplog, failure_kind, status, message,
):
    if failure_kind == "applicability":
        monkeypatch.setattr(
            file_app.server.WMUtils, "is_watermarking_applicable",
            Mock(side_effect=RuntimeError(SENSITIVE_CANARY)),
        )
        url = "/api/create-watermark/42"
        payload = WATERMARK
    elif failure_kind == "application":
        monkeypatch.setattr(
            file_app.server.WMUtils, "is_watermarking_applicable", Mock(return_value=True),
        )
        monkeypatch.setattr(
            file_app.server.WMUtils, "apply_watermark",
            Mock(side_effect=RuntimeError(SENSITIVE_CANARY)),
        )
        url = "/api/create-watermark/42"
        payload = WATERMARK
    else:
        monkeypatch.setattr(
            file_app.server.WMUtils, "read_watermark",
            Mock(side_effect=RuntimeError(SENSITIVE_CANARY)),
        )
        url = "/api/read-watermark/42"
        payload = {"method": "toy-eof", "key": "key"}

    response = file_app.client.post(
        url, headers=file_app.headers(), json=payload,
    )

    assert_sanitized_failure(response, caplog, status, message)


@pytest.mark.parametrize("failure_kind,status,message", [
    ("not-applicable", 400, "invalid watermarking request"),
    ("empty-output", 500, "watermarking failed"),
])
def test_watermark_failure_details_are_generic(
    file_app, monkeypatch, failure_kind, status, message,
):
    if failure_kind == "not-applicable":
        monkeypatch.setattr(
            file_app.server.WMUtils, "is_watermarking_applicable", Mock(return_value=False),
        )
    else:
        monkeypatch.setattr(
            file_app.server.WMUtils, "is_watermarking_applicable", Mock(return_value=True),
        )
        monkeypatch.setattr(
            file_app.server.WMUtils, "apply_watermark", Mock(return_value=b""),
        )

    response = file_app.client.post(
        "/api/create-watermark/42", headers=file_app.headers(), json=WATERMARK,
    )

    assert response.status_code == status
    assert response.get_json() == {"error": message}


def test_delete_file_error_uses_generic_note_and_log(
    file_app, monkeypatch, caplog,
):
    original_unlink = Path.unlink

    def fail_original(path, *args, **kwargs):
        if path == file_app.original:
            raise OSError(SENSITIVE_CANARY)
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_original)
    response = file_app.client.delete(
        "/api/delete-document/42", headers=file_app.headers(),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "deleted": True, "id": 42, "file_deleted": False,
        "file_missing": False, "note": "file deletion failed",
    }
    assert file_app.original.exists()
    assert SENSITIVE_CANARY not in response.get_data(as_text=True)
    assert SENSITIVE_CANARY not in caplog.text
    assert str(file_app.original) not in caplog.text
    with file_app.engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM Documents WHERE id = 42")
        ).scalar_one() == 0


@pytest.mark.parametrize("error,status,message", [
    (RuntimeError(SENSITIVE_CANARY), 500, "internal server error"),
    (InternalServerError(description=SENSITIVE_CANARY), 500, "internal server error"),
    (BadRequest(description=SENSITIVE_CANARY), 400, "request failed"),
])
def test_unhandled_api_exception_is_sanitized(
    file_app, monkeypatch, caplog, error, status, message,
):
    def fail_unexpectedly():
        raise error

    monkeypatch.setitem(
        file_app.app.view_functions,
        "get_watermarking_methods",
        fail_unexpectedly,
    )

    response = file_app.client.get("/api/get-watermarking-methods")

    assert_sanitized_failure(response, caplog, status, message)


@pytest.mark.parametrize("operation", ["upload", "watermark"])
def test_output_directory_symlink_cannot_escape(file_app, operation):
    env = file_app
    outside_dir = env.storage.parent / "outside-dir"
    outside_dir.mkdir()
    if operation == "upload":
        make_symlink(env.storage / "files", outside_dir)
        response = upload(env)
    else:
        make_symlink(env.original.parent / "watermarks", outside_dir)
        response = env.client.post(
            "/api/create-watermark/42", headers=env.headers(), json=WATERMARK,
        )
    assert response.status_code == 500
    assert list(outside_dir.iterdir()) == []


def test_upload_does_not_overwrite_existing_file(file_app, monkeypatch):
    env = file_app
    monkeypatch.setattr(env.server, "uuid4", lambda: SimpleNamespace(hex="a" * 32))
    first = upload(env)
    assert first.status_code == 201
    path = document_path(env, first.get_json()["id"])
    assert upload(env, content=PDF).status_code == 500
    assert path.read_bytes() == PDF


def test_watermark_names_are_safe_unique_and_downloadable(file_app):
    env = file_app
    with env.engine.begin() as conn:
        conn.execute(text("UPDATE Documents SET name = :name"), {"name": "../../odd\\name.pdf"})
    created = []
    for _ in range(2):
        response = env.client.post(
            "/api/create-watermark/42", headers=env.headers(),
            json={**WATERMARK, "intended_for": "../../reader\\name"},
        )
        assert response.status_code == 201, response.get_json()
        created.append(response.get_json())
    assert created[0]["filename"] != created[1]["filename"]
    for result in created:
        assert "/" not in result["filename"] and "\\" not in result["filename"]
        output = env.original.parent / "watermarks" / result["filename"]
        assert output.is_file()
        with env.client.get(f'/api/get-version/{result["link"]}') as download:
            assert download.status_code == 200
            marked_pdf = download.data
        assert marked_pdf.startswith(PDF)
        uploaded = upload(env, content=marked_pdf)
        assert uploaded.status_code == 201
        read = env.client.post(
            f'/api/read-watermark/{uploaded.get_json()["id"]}',
            headers=env.headers(), json=WATERMARK,
        )
        assert read.status_code == 201, read.get_json()
        assert read.get_json()["secret"] == WATERMARK["secret"]


def test_khaled_text_watermark_runs_alone_through_api(file_app):
    env = file_app
    with fitz.open() as document:
        page = document.new_page()
        sentence = "Khaled hides a recipient link in the spacing of these selectable letters."
        for row in range(40):
            page.insert_text((30, 35 + row * 18), sentence, fontsize=10)
        source = document.tobytes()
    env.original.write_bytes(source)

    method = "khaled-text-spacing-watermark"
    secret = "Group_13:" + "a" * 32
    key = "test-only-standalone-api-key"
    methods = env.client.get("/api/get-watermarking-methods").get_json()
    assert [item["name"] for item in methods["methods"]] == [
        "davide-watermark",
        "francesco-watermark",
        "khaled-text-spacing-watermark",
        "group13-watermark",
    ]

    created = env.client.post(
        "/api/create-watermark/42", headers=env.headers(),
        json={"method": method, "intended_for": "Group_13", "secret": secret, "key": key},
    )
    assert created.status_code == 201, created.get_json()
    assert created.get_json()["method"] == method
    downloaded = env.client.get(f'/api/get-version/{created.get_json()["link"]}')
    assert downloaded.status_code == 200
    marked = downloaded.data
    with fitz.open(stream=source, filetype="pdf") as original, \
         fitz.open(stream=marked, filetype="pdf") as watermarked:
        assert [page.get_text() for page in watermarked] == [page.get_text() for page in original]

    uploaded = upload(env, content=marked)
    assert uploaded.status_code == 201, uploaded.get_json()
    for reader in (method, "group13-watermark"):
        read = env.client.post(
            f'/api/read-watermark/{uploaded.get_json()["id"]}',
            headers=env.headers(), json={"method": reader, "key": key},
        )
        assert read.status_code == 201, read.get_json()
        assert read.get_json()["secret"] == secret


@pytest.mark.parametrize("relative", [False, True])
def test_existing_stored_paths_still_download_and_delete(file_app, relative):
    env = file_app
    if relative:
        set_paths(env, env.original.relative_to(env.storage).as_posix())
    for url in ["/api/get-document/42", "/api/get-version/shared"]:
        with env.client.get(url, headers=env.headers()) as response:
            assert response.status_code == 200
            assert response.data == PDF
    assert env.client.delete("/api/delete-document/42", headers=env.headers()).status_code == 200
    assert not env.original.exists()


def test_upload_rejects_malformed_page_tree(file_app):
    env = file_app
    malformed_pdf = (
        Path(__file__).parent / "fixtures" / "malformed-page-tree.pdf"
    ).read_bytes()

    response = upload(env, filename="malformed.pdf", content=malformed_pdf)

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid PDF document"}

    assert env.original.read_bytes() == PDF
    assert env.outside.read_bytes() == b"outside sentinel"
    assert {p for p in env.storage.rglob("*") if p.is_file()} == {
        env.original
    }

    with env.engine.connect() as connection:
        assert connection.execute(
            text("SELECT COUNT(*) FROM Documents")
        ).scalar_one() == 1
        assert connection.execute(
            text("SELECT COUNT(*) FROM Versions")
        ).scalar_one() == 1
