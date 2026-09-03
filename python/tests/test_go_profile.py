from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).parents[2] / "analysis" / "go-profile"
loader = importlib.machinery.SourceFileLoader("jaq_go_profile", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
assert spec is not None
module = importlib.util.module_from_spec(spec)
sys.modules[loader.name] = module
loader.exec_module(module)


class GoProfileTest(unittest.TestCase):
    @staticmethod
    def clone_block(base: int):
        pattern = (
            ("mov", ("reg", "imm")),
            ("mov", ("mem", "reg")),
            ("add", ("reg", "imm")),
            ("cmp", ("reg", "imm")),
            ("jne", ("imm",)),
            ("xor", ("reg", "reg")),
        )
        return [
            module.Instruction(base + index, mnemonic, operands)
            for index, (mnemonic, operands) in enumerate(pattern * 4)
        ]

    def test_clone_dominated_go_profile_prioritizes_unique_sensitive_residue(self):
        main = self.clone_block(0x1000) + [
            module.Instruction(0x1100, "call", ("imm",), "main.worker", 0x2000),
            module.Instruction(0x1105, "call", ("imm",), "crypto/sha1.Sum", 0x5000),
            module.Instruction(0x110A, "call", ("imm",), "syscall.(*LazyProc).Call", 0x6000),
        ]
        worker = self.clone_block(0x2000) + [
            module.Instruction(0x2100, "call", ("imm",), "kernel32.dll!WriteFile", 0x7000),
        ]
        third = self.clone_block(0x3000) + [
            module.Instruction(0x3100, "ret"),
        ]
        profile = module._profile_functions([
            module.FunctionIR("main.main", 0x1000, 0x200, main),
            module.FunctionIR("main.worker", 0x2000, 0x200, worker),
            module.FunctionIR("main.padding", 0x3000, 0x200, third),
        ], image_base=0x400000, entry_rva=0x1000)
        self.assertTrue(profile["clone_dominated"])
        self.assertEqual(profile["coverage_status"], "partial")
        self.assertIn("main.worker", profile["reachable_main_functions"])
        self.assertTrue(profile["dynamic_resolution"]["negative_capability_claims_blocked"])
        by_name = {item["name"]: item for item in profile["functions"]}
        main_targets = {item["target"] for item in by_name["main.main"]["unique_calls"]}
        self.assertIn("crypto/sha1.Sum", main_targets)
        self.assertIn("syscall.(*LazyProc).Call", main_targets)
        self.assertEqual(by_name["main.main"]["priority"], "high")

    def test_sensitive_repeated_cluster_is_never_deprioritized(self):
        functions = []
        for index, name in enumerate(("main.main", "main.worker", "main.other")):
            base = 0x1000 * (index + 1)
            block = [
                module.Instruction(base + offset, "call", ("imm",), "kernel32.dll!connect", 0x9000)
                if offset == 5 else module.Instruction(base + offset, "mov", ("reg", "imm"))
                for offset in range(16)
            ]
            functions.append(module.FunctionIR(name, base, 0x100, block))
        profile = module._profile_functions(functions)
        sensitive = [item for item in profile["clone_clusters"] if item["sensitive"]]
        self.assertTrue(sensitive)
        self.assertTrue(all(item["disposition"] == "review" for item in sensitive))

    def test_non_pe_is_reported_without_execution(self):
        profile = module.profile_bytes(b"not a portable executable")
        self.assertFalse(profile["detected"])
        self.assertEqual(profile["status"], "not_pe")


if __name__ == "__main__":
    unittest.main()
