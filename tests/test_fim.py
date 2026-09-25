"""Unit tests for Sentinel Cryptographic File Integrity Monitoring (FIM)."""
from __future__ import annotations
import sys, os, tempfile, shutil
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.core.plugins.fim_plugin import FimPlugin, _hash_file


def test_fim_plugin_instantiation():
    fp = FimPlugin()
    assert fp.name == "fim_audit"
    assert fp.stage == "audit"


def test_file_hashing():
    td = tempfile.mkdtemp()
    try:
        tf = os.path.join(td, "passwd_test")
        with open(tf, "w") as f:
            f.write("root:x:0:0:root:/root:/bin/bash\n")

        h1 = _hash_file(tf)
        assert h1 is not None and len(h1) == 64

        # Append data to simulate tampering
        with open(tf, "a") as f:
            f.write("backdoor:x:0:0::/root:/bin/bash\n")

        h2 = _hash_file(tf)
        assert h1 != h2
    finally:
        shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    test_fim_plugin_instantiation()
    print("PASS test_fim_plugin_instantiation")
    test_file_hashing()
    print("PASS test_file_hashing")
    print("ALL FIM TESTS PASSED")
