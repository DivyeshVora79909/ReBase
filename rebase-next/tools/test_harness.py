#!/usr/bin/env python3
"""Independent positive and injected-corruption controls for archive observations."""

import copy
import json
import unittest

from harness import check_archive


def image(epoch):
    names = ("native_kv", "public_records", "reader_records", "authority", "operations",
             "receipt_slots", "query_epochs", "local_runtime", "effect_executions",
             "effect_due", "effect_facts", "effect_inbox", "effect_runtime")
    tables = {name: [{"key": "01", "value": "aa"}] for name in names}
    header = {"format": "rebase-store-10", "store_id": "00000000-0000-0000-0000-000000000001",
              "cursor_key": "11" * 32, "operation_epoch": str(epoch)}
    tables["local_runtime"] = [{"key": b"header".hex(), "value": json.dumps(header).encode().hex()}]
    return {"format": "rebase-authorized-observation-1", "complete": True, "tables": tables}


class ArchiveOracleControls(unittest.TestCase):
    def setUp(self):
        self.before = image(7)
        self.after = image(8)
        self.after["tables"]["operations"] = []
        self.after["tables"]["receipt_slots"] = []

    def test_exact_cleanup_accepts_preserved_domain_authority_and_effects(self):
        check_archive(self.before, self.after)

    def test_incomplete_changed_or_unexpired_images_reject(self):
        damaged = []
        for name in self.after["tables"]:
            if name not in ("operations", "receipt_slots", "local_runtime"):
                changed = copy.deepcopy(self.after)
                changed["tables"][name] = []
                damaged.append((name, changed))
        for name in ("operations", "receipt_slots"):
            changed = copy.deepcopy(self.after)
            changed["tables"][name] = copy.deepcopy(self.before["tables"][name])
            damaged.append(("retained " + name, changed))
        for field, value in (("operation_epoch", "7"), ("operation_epoch", "9"),
                             ("store_id", "00000000-0000-0000-0000-000000000002"),
                             ("cursor_key", "22" * 32)):
            changed = copy.deepcopy(self.after)
            row = changed["tables"]["local_runtime"][0]
            header = json.loads(bytes.fromhex(row["value"]))
            header[field] = value
            row["value"] = json.dumps(header).encode().hex()
            damaged.append((field, changed))
        incomplete = copy.deepcopy(self.after)
        incomplete["complete"] = False
        damaged.append(("incomplete", incomplete))
        missing = copy.deepcopy(self.after)
        del missing["tables"]["query_epochs"]
        damaged.append(("missing table", missing))
        for name, changed in damaged:
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                check_archive(self.before, changed)


if __name__ == "__main__":
    unittest.main()
