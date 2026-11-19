"""Code integrity and anti-tamper security checks.
Locked to author: Anurag Sharma
Developer PIN: 210104
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, ".")
from studio import config, security

fails = []


def check(name, ok, extra=""):
    print(("PASS " if ok else "FAIL ") + name + (f"  {extra}" if extra and not ok else ""))
    if not ok:
        fails.append(name)


# 1. PIN Verification
check("master PIN 210104 accepted", security.check_pin("210104"))
check("PIN with whitespace accepted", security.check_pin(" 210104 "))
check("wrong PIN rejected", not security.check_pin("123456"))
check("empty PIN rejected", not security.check_pin(""))
check("arbitrary PIN rejected", not security.check_pin("000000"))

# 2. Author Attribution
check("security author is Anurag Sharma", security.AUTHOR == "Anurag Sharma")
check("config legal name is Anurag Sharma", config.LEGAL_NAME == "Anurag Sharma")

# 3. Integrity Verification
ok, reasons = security.verify()
check("codebase integrity intact", ok, str(reasons))
check("no tampering reasons on clean seal", len(reasons) == 0, str(reasons))
check("system is not locked", not security.is_locked())

# 4. Tamper Detection & Master PIN Unlock Flow
data = json.loads(security.MANIFEST_PATH.read_text(encoding="utf-8"))
saved_files = data.get("files", {})

# Tamper with a hash in manifest
fake_data = dict(data)
fake_data["files"] = dict(saved_files)
fake_data["files"]["studio/config.py"] = "0000000000000000000000000000000000000000000000000000000000000000"

try:
    security.MANIFEST_PATH.write_text(json.dumps(fake_data), encoding="utf-8")
    tamper_ok, tamper_reasons = security.verify()
    check("tamper detected when hash differs", not tamper_ok)
    check("system enters locked mode", security.is_locked())
    check("reasons identify altered file", any("studio/config.py" in r for r in tamper_reasons))

    # Wrong PIN fails to unlock
    fail_unlock, _ = security.unlock_and_seal("wrong_pin")
    check("wrong PIN fails unlock", not fail_unlock)
    check("system remains locked", security.is_locked())

    # Master PIN 210104 unlocks and re-seals
    pass_unlock, msg = security.unlock_and_seal("210104")
    check("PIN 210104 unlocks system", pass_unlock, msg)
    check("system lock is cleared", not security.is_locked())
    after_ok, _ = security.verify()
    check("verification passes after re-seal", after_ok)

finally:
    # Ensure genuine seal is restored
    security.seal("210104")

if fails:
    print(f"\n{len(fails)} failed")
    sys.exit(1)
print(f"\n  ALL PASSED\n  17 checks passed")
