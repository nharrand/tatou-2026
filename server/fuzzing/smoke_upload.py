import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from pytest import MonkeyPatch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "test" / "api"))

from test_file_paths import (
    PDF,
    document_path,
    file_app,
    upload,
)


def main():
    with TemporaryDirectory(prefix="tatou-fuzz-") as directory, MonkeyPatch.context() as patch:
        # Reuse the existing isolated database/storage setup.
        setup = file_app.__wrapped__(Path(directory), patch)
        env = next(setup)

        try:
            response = upload(
                env,
                filename="seed.pdf",
                content=PDF,
            )

            print("HTTP status:", response.status_code)
            assert response.status_code == 201, response.get_json()

            saved = document_path(env, response.get_json()["id"])
            assert saved.read_bytes() == PDF

            print("Smoke check passed: PDF uploaded and stored correctly.")
        finally:
            # Finish the fixture and dispose of its test database.
            next(setup, None)


if __name__ == "__main__":
    main()
