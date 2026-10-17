import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import atheris
from pytest import MonkeyPatch
from sqlalchemy import text

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "test" / "api")
)

from test_file_paths import PDF, document_path, file_app, upload

# Configure the isolated test environment before importing the app.
os.environ["SECRET_KEY"] = "local-fuzzing-test-key-only"

# Instrument the application before the fixture imports it.
with atheris.instrument_imports():
    import server  # noqa: F401 - imported here for Atheris instrumentation


@atheris.instrument_func
def test_one_input(data):
    # Fresh storage and database prevent inputs affecting each other.
    with TemporaryDirectory(prefix="tatou-fuzz-") as directory, MonkeyPatch.context() as patch:
        setup = file_app.__wrapped__(Path(directory), patch)
        env = next(setup)

        try:
            response = upload(
                env, filename="fuzz.pdf", content=data
            )

            assert response.status_code in (201, 400, 413), (
                response.status_code,
                response.get_data(as_text=True)[:500],
            )

            expected_files = {env.original.resolve()}
            expected_rows = 1

            if response.status_code == 201:
                body = response.get_json()
                saved = document_path(env, body["id"])

                assert saved.resolve().is_relative_to(
                    (env.storage / "files" / "7").resolve()
                ), "Uploaded file escaped its storage directory"

                assert saved.read_bytes() == data, (
                    "Stored bytes differ from uploaded bytes"
                )
                assert body["size"] == len(data)

                expected_files.add(saved.resolve())
                expected_rows = 2

            actual_files = {
                p.resolve()
                for p in env.storage.rglob("*")
                if p.is_file()
            }
            assert actual_files == expected_files, (
                "Unexpected or leftover files"
            )

            with env.engine.connect() as connection:
                count = connection.execute(
                    text("SELECT COUNT(*) FROM Documents")
                ).scalar_one()
            assert count == expected_rows, (
                "Unexpected database changes"
            )

            assert env.original.read_bytes() == PDF
            assert env.outside.read_bytes() == b"outside sentinel"

        finally:
            next(setup, None)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
