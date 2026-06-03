"""Unit tests for trace_engine.storage — LocalStorage and GCSStorage.

GCS tests mock the google.cloud.storage client so no real GCP credentials
are required.  LocalStorage tests use tmp_path (pytest built-in fixture).
"""

from __future__ import annotations

import sys
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — inject a fake google.cloud.storage module so GCSStorage can be
# imported even without the real package installed.
# ---------------------------------------------------------------------------


def _make_fake_gcs_module() -> ModuleType:
    """Build a minimal fake google.cloud.storage module tree."""
    # google namespace
    google_mod = ModuleType("google")
    google_mod.__path__ = []  # type: ignore[attr-defined]

    # google.cloud namespace
    cloud_mod = ModuleType("google.cloud")
    cloud_mod.__path__ = []  # type: ignore[attr-defined]

    # google.cloud.storage
    storage_mod = ModuleType("google.cloud.storage")

    class FakeBlob:
        def __init__(self, name: str, bucket: Any) -> None:
            self.name = name
            self._bucket = bucket
            self._data: bytes | None = None

        def exists(self) -> bool:
            return self.name in self._bucket._objects

        def upload_from_string(self, data: bytes, content_type: str = "") -> None:
            self._bucket._objects[self.name] = data

        def download_as_text(self, encoding: str = "utf-8") -> str:
            raw = self._bucket._objects.get(self.name)
            if raw is None:
                raise FileNotFoundError(self.name)
            return raw.decode(encoding)

    class FakeBlobListIterator:
        """Iterable returned by list_blobs."""

        def __init__(self, blobs: list[FakeBlob]) -> None:
            self._blobs = blobs
            self.pages = iter([blobs])  # unused but kept for structural parity

        def __iter__(self):
            return iter(self._blobs)

    class FakeBucket:
        def __init__(self, name: str) -> None:
            self.name = name
            self._objects: dict[str, bytes] = {}

        def blob(self, name: str) -> FakeBlob:
            return FakeBlob(name, self)

    class FakeClient:
        def __init__(self) -> None:
            self._buckets: dict[str, FakeBucket] = {}

        def bucket(self, name: str) -> FakeBucket:
            if name not in self._buckets:
                self._buckets[name] = FakeBucket(name)
            return self._buckets[name]

        def list_blobs(
            self,
            bucket_name: str,
            prefix: str = "",
            delimiter: str = "",
        ) -> FakeBlobListIterator:
            bucket = self._buckets.get(bucket_name, FakeBucket(bucket_name))
            matching = [
                FakeBlob(k, bucket) for k in sorted(bucket._objects) if k.startswith(prefix)
            ]
            return FakeBlobListIterator(matching)

    storage_mod.Client = FakeClient  # type: ignore[attr-defined]
    storage_mod.Blob = FakeBlob  # type: ignore[attr-defined]

    return google_mod, cloud_mod, storage_mod


# Register the fake module once for the entire test session.
_GOOGLE_MOD, _CLOUD_MOD, _STORAGE_MOD = _make_fake_gcs_module()


def _patch_gcs_import():
    """Context manager: replace google.cloud.storage with the fake module."""
    return patch.dict(
        sys.modules,
        {
            "google": _GOOGLE_MOD,
            "google.cloud": _CLOUD_MOD,
            "google.cloud.storage": _STORAGE_MOD,
        },
    )


# ---------------------------------------------------------------------------
# StorageBackend ABC tests
# ---------------------------------------------------------------------------


class TestStorageBackendABC:
    def test_cannot_instantiate_directly(self):
        from trace_engine.storage.backend import StorageBackend

        with pytest.raises(TypeError):
            StorageBackend()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# LocalStorage tests
# ---------------------------------------------------------------------------


class TestLocalStorage:
    def test_save_and_load_str(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "bundle_202605251700.json", '{"type": "bundle"}')
        result = storage.load("stix", "bundle_202605251700.json")
        assert result == '{"type": "bundle"}'

    def test_save_and_load_bytes(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "data.bin", b"\x00\x01\x02")
        raw = (tmp_path / "stix" / "data.bin").read_bytes()
        assert raw == b"\x00\x01\x02"

    def test_creates_category_directory(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "bundle_202605251700.json", "{}")
        assert (tmp_path / "stix").is_dir()

    def test_correct_file_path(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("plans", "collection_plan_202605251700.md", "# Plan")
        expected = tmp_path / "plans" / "collection_plan_202605251700.md"
        assert expected.exists()
        assert expected.read_text(encoding="utf-8") == "# Plan"

    def test_list_files_empty_category(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        assert storage.list_files("nonexistent") == []

    def test_list_files_returns_sorted_filenames(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "bundle_b.json", "b")
        storage.save("stix", "bundle_a.json", "a")
        storage.save("stix", "bundle_c.json", "c")
        assert storage.list_files("stix") == ["bundle_a.json", "bundle_b.json", "bundle_c.json"]

    def test_exists_true(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "bundle.json", "{}")
        assert storage.exists("stix", "bundle.json") is True

    def test_exists_false(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        assert storage.exists("stix", "missing.json") is False

    def test_load_missing_raises_file_not_found(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        with pytest.raises(FileNotFoundError):
            storage.load("stix", "does_not_exist.json")

    def test_overwrite_existing_file(self, tmp_path):
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        storage.save("stix", "file.json", "first")
        storage.save("stix", "file.json", "second")
        assert storage.load("stix", "file.json") == "second"

    def test_timestamp_filename_format(self, tmp_path):
        """Filename with YYYYMMDDHHmm suffix is accepted and stored correctly."""
        from trace_engine.storage.local import LocalStorage

        storage = LocalStorage(base_dir=tmp_path)
        fname = "stix_bundle_202605251700.json"
        storage.save("stix", fname, "{}")
        assert storage.exists("stix", fname)
        assert fname in storage.list_files("stix")


# ---------------------------------------------------------------------------
# GCSStorage tests (mocked google-cloud-storage)
# ---------------------------------------------------------------------------


class TestGCSStorage:
    def test_save_and_load_str(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="trace")
            storage.save("stix", "bundle_202605251700.json", '{"type":"bundle"}')
            result = storage.load("stix", "bundle_202605251700.json")
            assert result == '{"type":"bundle"}'

    def test_save_bytes(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="")
            storage.save("stix", "bundle.json", b'{"type":"bundle"}')
            result = storage.load("stix", "bundle.json")
            assert result == '{"type":"bundle"}'

    def test_blob_name_with_prefix(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="mybucket", prefix="prod")
            blob_name = storage._blob_name("stix", "bundle_202605251700.json")
            assert blob_name == "prod/stix/bundle_202605251700.json"

    def test_blob_name_without_prefix(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="mybucket", prefix="")
            blob_name = storage._blob_name("stix", "bundle_202605251700.json")
            assert blob_name == "stix/bundle_202605251700.json"

    def test_exists_true(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="")
            storage.save("plans", "collection_plan_202605251700.md", "# Plan")
            assert storage.exists("plans", "collection_plan_202605251700.md") is True

    def test_exists_false(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="")
            assert storage.exists("stix", "missing.json") is False

    def test_load_missing_raises_file_not_found(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="")
            with pytest.raises(FileNotFoundError):
                storage.load("stix", "does_not_exist.json")

    def test_list_files_empty(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="empty-bucket", prefix="")
            assert storage.list_files("stix") == []

    def test_list_files_returns_filenames(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            storage = gcs_mod.GCSStorage(bucket="test-bucket", prefix="")
            storage.save("stix", "bundle_b.json", "b")
            storage.save("stix", "bundle_a.json", "a")
            files = storage.list_files("stix")
            assert "bundle_a.json" in files
            assert "bundle_b.json" in files

    def test_import_error_without_package(self, monkeypatch):
        """GCSStorage raises ImportError if google-cloud-storage is absent."""
        # Remove the fake module to simulate missing package
        with patch.dict(
            sys.modules,
            {"google.cloud.storage": None, "google.cloud": None, "google": None},
        ):
            import importlib

            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)

            with pytest.raises(ImportError, match="google-cloud-storage"):
                gcs_mod.GCSStorage(bucket="x")


# ---------------------------------------------------------------------------
# create_storage_backend factory tests
# ---------------------------------------------------------------------------


class TestCreateStorageBackend:
    def test_local_backend_by_default(self, tmp_path):
        from trace_engine.storage import create_storage_backend

        class _Cfg:
            trace_storage = "local"
            trace_storage_base_dir = str(tmp_path)
            trace_storage_bucket = ""
            trace_storage_prefix = ""

        backend = create_storage_backend(_Cfg())
        from trace_engine.storage.local import LocalStorage

        assert isinstance(backend, LocalStorage)

    def test_local_backend_writes_to_base_dir(self, tmp_path):
        from trace_engine.storage import create_storage_backend

        class _Cfg:
            trace_storage = "local"
            trace_storage_base_dir = str(tmp_path)
            trace_storage_bucket = ""
            trace_storage_prefix = ""

        backend = create_storage_backend(_Cfg())
        backend.save("stix", "test.json", "{}")
        assert (tmp_path / "stix" / "test.json").exists()

    def test_gcs_backend_selected(self):
        with _patch_gcs_import():
            import importlib

            import trace_engine.storage as storage_pkg
            import trace_engine.storage.gcs as gcs_mod

            importlib.reload(gcs_mod)
            importlib.reload(storage_pkg)

            class _Cfg:
                trace_storage = "gcs"
                trace_storage_base_dir = "output"
                trace_storage_bucket = "my-bucket"
                trace_storage_prefix = "trace"

            backend = storage_pkg.create_storage_backend(_Cfg())
            assert isinstance(backend, gcs_mod.GCSStorage)

    def test_gcs_requires_bucket(self):
        from trace_engine.storage import create_storage_backend

        class _Cfg:
            trace_storage = "gcs"
            trace_storage_base_dir = "output"
            trace_storage_bucket = ""
            trace_storage_prefix = ""

        with pytest.raises(ValueError, match="TRACE_STORAGE_BUCKET"):
            create_storage_backend(_Cfg())

    def test_unknown_backend_raises_value_error(self):
        from trace_engine.storage import create_storage_backend

        class _Cfg:
            trace_storage = "s3"
            trace_storage_base_dir = "output"
            trace_storage_bucket = ""
            trace_storage_prefix = ""

        with pytest.raises(ValueError, match="s3"):
            create_storage_backend(_Cfg())


# ---------------------------------------------------------------------------
# Config integration tests
# ---------------------------------------------------------------------------


class TestConfigStorageFields:
    def test_default_backend_is_local(self, monkeypatch):
        monkeypatch.delenv("TRACE_STORAGE", raising=False)
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage == "local"

    def test_default_base_dir_is_output(self, monkeypatch):
        monkeypatch.delenv("TRACE_STORAGE_BASE_DIR", raising=False)
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage_base_dir == "output"

    def test_env_overrides_backend(self, monkeypatch):
        monkeypatch.setenv("TRACE_STORAGE", "gcs")
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage == "gcs"

    def test_env_overrides_base_dir(self, monkeypatch):
        monkeypatch.setenv("TRACE_STORAGE_BASE_DIR", "/tmp/trace_out")
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage_base_dir == "/tmp/trace_out"

    def test_env_overrides_gcs_bucket(self, monkeypatch):
        monkeypatch.setenv("TRACE_STORAGE_BUCKET", "my-test-bucket")
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage_bucket == "my-test-bucket"

    def test_env_overrides_gcs_prefix(self, monkeypatch):
        monkeypatch.setenv("TRACE_STORAGE_PREFIX", "prod/trace")
        from importlib import reload

        import trace_engine.config as cfg_mod

        reload(cfg_mod)
        cfg = cfg_mod.load_config()
        assert cfg.trace_storage_prefix == "prod/trace"
