#!/usr/bin/env python3
"""Independent extracted-payload and feature controls; no Cargo or database."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import tarfile
import io
import unittest
from unittest.mock import patch

import package


class BundleControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "src/bin/rebase-next.rs",
                     "tools/client.py", "tools/harness.py", "tools/g8.py", "deploy/server.example.json",
                     *package.TEMPLATES.values()):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("a required committed input\n")
        source_files = {str(path.relative_to(self.root)): package.digest(path)
                        for path in self.root.rglob("*") if path.is_file()}
        binary = self.root / "bin/rebase-next"
        binary.parent.mkdir()
        binary.write_bytes(b"synthetic executable for metadata-only controls")
        self.catalogs, self.identities, models = {}, {}, {}
        for name in package.MODELS:
            identity = {"version": "0.16.0", "store_format": "rebase-store-10",
                        "model": hashlib.sha256(name.encode()).hexdigest()}
            catalog = {"model": identity["model"], "api": "rebase-local-api-4",
                       "codec": "native-slice-kv-7", "contracts": [{"code": 101}],
                       "capabilities": {"limits": {"receipts": 1024}}}
            if name == "effect-demo":
                catalog["capabilities"]["effects"] = {"codec": "rebase-effects-4"}
            self.catalogs[name], self.identities[name] = deepcopy(catalog), deepcopy(identity)
            path = self.root / f"catalogs/{name}.public.json"
            path.parent.mkdir(exist_ok=True)
            package.write_json(path, catalog)
            models[name] = {**package.model_identity(identity, catalog, "0.16.0"),
                            "behavior_contract": name + "-test-1",
                            "catalog": str(path.relative_to(self.root)),
                            "catalog_sha256": package.digest(path)}
        self.manifest = {
            "format": "rebase-deployment-bundle-2", "package_version": "0.16.0",
            "source_commit": "a" * 40, "source_tree": "b" * 40, "source_files": source_files,
            "binary_sha256": package.digest(binary), "models": models,
            "supported_backends": ["redb"], "deployment_templates": {"redb": package.TEMPLATES["redb"]},
            "formats": {"store": "rebase-store-10", "native_codec": "native-slice-kv-7",
                        "effect_codec": "rebase-effects-4", "api": "rebase-local-api-4"},
            "build": {"profile": "release", "jobs": 2, "features": [], "locked": True,
                      "incremental": False, "outside_git": True},
            "platform": {"shared_libraries": ["libc.so.6"]},
            "native_prerequisites": {"foundationdb": {
                "required": False, "bundled": False, "library": "libfdb_c"}},
        }
        self.publish()

    def publish(self):
        package.write_json(self.root / "BUNDLE.json", self.manifest)
        rows = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.name != "SHA256SUMS":
                rows.append(f"{package.digest(path)}  {path.relative_to(self.root)}\n")
        (self.root / "SHA256SUMS").write_text("".join(rows))

    def test_complete_metadata_payload_passes(self):
        checked = package.check_bundle(self.root, check_binary=False)
        self.assertEqual(checked["status"], "passed")
        self.assertEqual(checked["model_count"], 6)
        self.assertFalse(checked["binary_catalogs_checked"])
        self.assertEqual(checked["supported_backends"], ["redb"])

    def test_changed_and_missing_payload_fail(self):
        target = self.root / "tools/client.py"
        target.write_text("changed\n")
        with self.assertRaisesRegex(RuntimeError, "checksum differs"):
            package.check_bundle(self.root, check_binary=False)
        target.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing or nonregular"):
            package.verify_checksums(self.root)

    def test_removed_required_source_and_model_fail_even_with_updated_checksums(self):
        del self.manifest["source_files"]["tools/g8.py"]
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "required committed bundle input"):
            package.check_bundle(self.root, check_binary=False)
        del self.manifest["models"]["quantity"]
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "source/model inventory is incomplete"):
            package.check_bundle(self.root, check_binary=False)

    def test_wrong_catalog_identity_is_rejected(self):
        catalog = deepcopy(self.catalogs["equipment"])
        catalog["model"] = "0" * 64
        path = self.root / "catalogs/equipment.public.json"
        package.write_json(path, catalog)
        self.manifest["models"]["equipment"]["catalog_sha256"] = package.digest(path)
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "compiled package/catalog identity"):
            package.check_bundle(self.root, check_binary=False)

    def test_recorded_catalog_cannot_override_the_extracted_executable(self):
        catalog = deepcopy(self.catalogs["calculation"])
        catalog["capabilities"]["limits"]["receipts"] = 2048
        path = self.root / "catalogs/calculation.public.json"
        package.write_json(path, catalog)
        self.manifest["models"]["calculation"].update(
            limits=deepcopy(catalog["capabilities"]["limits"]), catalog_sha256=package.digest(path))
        self.publish()
        self.assertEqual(package.check_bundle(self.root, check_binary=False)["status"], "passed")

        def actual_binary(_binary, _model_option, name, command, *args, **_kwargs):
            if command == "version":
                return json.dumps(self.identities[name]).encode()
            if args == ("public",):
                return json.dumps(self.catalogs[name]).encode()
            return json.dumps({"behavior_contract": name + "-test-1"}).encode()

        with patch("package.command", side_effect=actual_binary):
            with self.assertRaisesRegex(RuntimeError, "extracted executable/catalog differs"):
                package.check_bundle(self.root)

    def test_shared_formats_and_library_prerequisites_are_checked(self):
        self.manifest["formats"]["store"] = "rebase-store-9"
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "shared model format"):
            package.check_bundle(self.root, check_binary=False)
        self.manifest["formats"]["store"] = "rebase-store-10"
        self.manifest["platform"]["shared_libraries"].append("libfdb_c.so")
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "feature/native-library"):
            package.check_bundle(self.root, check_binary=False)

    def test_feature_backend_build_and_template_claims_are_checked(self):
        self.manifest["supported_backends"] = ["redb", "surrealkv"]
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "feature/backend"):
            package.check_bundle(self.root, check_binary=False)
        self.manifest["supported_backends"] = ["redb"]
        self.manifest["build"]["jobs"] = 8
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "build contract"):
            package.check_bundle(self.root, check_binary=False)
        self.manifest["build"]["jobs"] = 2
        self.manifest["deployment_templates"] = {}
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "deployment template"):
            package.check_bundle(self.root, check_binary=False)

    def test_selected_backend_templates_and_default_fdb_absence(self):
        self.assertEqual(package.check_bundle(self.root, check_binary=False)["features"], [])
        self.assertNotIn("libfdb_c.so", self.manifest["platform"]["shared_libraries"])
        self.manifest["build"]["features"] = ["surrealkv"]
        self.manifest["supported_backends"] = ["redb", "surrealkv"]
        self.manifest["deployment_templates"] = {
            name: package.TEMPLATES[name] for name in self.manifest["supported_backends"]}
        self.publish()
        checked = package.check_bundle(self.root, check_binary=False)
        self.assertEqual(checked["features"], ["surrealkv"])
        self.assertEqual(checked["supported_backends"], ["redb", "surrealkv"])
        self.manifest["build"]["features"] = ["foundationdb"]
        self.manifest["supported_backends"] = ["redb", "foundationdb"]
        self.manifest["deployment_templates"] = {
            name: package.TEMPLATES[name] for name in self.manifest["supported_backends"]}
        self.manifest["platform"]["shared_libraries"].append("libfdb_c.so.7.3")
        self.manifest["native_prerequisites"]["foundationdb"]["required"] = True
        self.publish()
        checked = package.check_bundle(self.root, check_binary=False)
        self.assertEqual(checked["features"], ["foundationdb"])
        self.assertEqual(checked["supported_backends"], ["redb", "foundationdb"])
        self.manifest["native_prerequisites"]["foundationdb"]["bundled"] = True
        self.publish()
        with self.assertRaisesRegex(RuntimeError, "runtime prerequisite"):
            package.check_bundle(self.root, check_binary=False)

    def test_trusted_source_extraction_rejects_traversal_and_links(self):
        for member in ("../outside", "link"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temp:
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w") as archive:
                    if member == "link":
                        info = tarfile.TarInfo(member)
                        info.type = tarfile.SYMTYPE
                        info.linkname = "../../outside"
                        archive.addfile(info)
                    else:
                        info = tarfile.TarInfo(member)
                        info.size = 1
                        archive.addfile(info, io.BytesIO(b"x"))
                raw.seek(0)
                with tarfile.open(fileobj=raw) as archive:
                    with self.assertRaisesRegex(RuntimeError, "bounded regular"):
                        package.extract_trusted_sources(archive, Path(temp))

    def test_duplicate_checksum_path_escape_and_symlink_are_rejected(self):
        inventory = self.root / "SHA256SUMS"
        original = inventory.read_text()
        inventory.write_text(original + original.splitlines()[0] + "\n")
        with self.assertRaisesRegex(RuntimeError, "duplicate checksum"):
            package.verify_checksums(self.root)
        for name in ("../escape", "/absolute", "tools/../escape", "tools//client.py", "tools\\client.py"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(RuntimeError, "invalid bundle-relative"):
                    package.payload_path(self.root, name)
        inventory.write_text(original)
        target = self.root / "tools/client.py"
        target.unlink()
        target.symlink_to(self.root / "tools/harness.py")
        with self.assertRaisesRegex(RuntimeError, "nonregular"):
            package.verify_checksums(self.root)

    def test_unknown_and_ambiguous_features_reject(self):
        self.assertEqual(package.selected_features(""), [])
        self.assertEqual(package.selected_features("surrealkv,foundationdb"), ["foundationdb", "surrealkv"])
        self.assertEqual(package.backend_names(["foundationdb", "surrealkv"]),
                         ["redb", "foundationdb", "surrealkv"])
        for value in ("default", "foundationdb,foundationdb", "foundationdb,", " surrealkv", "tikv"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    package.selected_features(value)

    def test_named_format_contracts_reject_numeric_and_incomplete_fixtures(self):
        identity, catalog = self.identities["equipment"], self.catalogs["equipment"]
        self.assertEqual(package.model_identity(identity, catalog, "0.16.0")["store_format"], "rebase-store-10")
        for value in (10, True, "rebase-store-", "rebase-store-0", "10"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "identity differs or is incomplete"):
                    package.model_identity({**identity, "store_format": value}, catalog, "0.16.0")
        for key, value in (("api", "rebase-local-api-"), ("codec", "native-slice-kv-")):
            with self.subTest(key=key):
                with self.assertRaisesRegex(RuntimeError, "identity differs or is incomplete"):
                    package.model_identity(identity, {**catalog, key: value}, "0.16.0")


if __name__ == "__main__":
    unittest.main()
