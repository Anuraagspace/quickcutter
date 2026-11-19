"""QuickCutter Code Integrity & Anti-Tamper Security Guard.
Author & Owner: Anurag Sharma
Project: QuickCutter

Protects the project files and author identity against unauthorized modification.
If any core file or author signature is tampered with, the system enters lockdown mode
and requires the Developer Master Security PIN (210104) to unlock and re-seal.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from . import config

AUTHOR = "Anurag Sharma"
PROJECT = "QuickCutter"
SALT = b"quickcutter_anurag_sharma_salt_v1"
PIN_HASH = "a07f8f51ea1ce13a6e9264cc915822c098b0f4a9a3bde191de434c738f47cc0d"  # SHA-256 of salt + '210104'
MANIFEST_PATH = Path(__file__).resolve().parent / ".security_manifest.json"

# In-memory security status
_is_locked = False
_tamper_reasons = []


def check_pin(pin: str) -> bool:
    """Validate master developer security PIN."""
    if not pin:
        return False
    candidate = hashlib.sha256(SALT + str(pin).strip().encode("utf-8")).hexdigest()
    return candidate == PIN_HASH


def _hash_file(path: Path) -> str:
    """Compute normalized SHA-256 hash (CRLF normalized to LF)."""
    try:
        content = path.read_bytes().replace(b"\r\n", b"\n")
        return hashlib.sha256(content).hexdigest()
    except Exception:
        return ""


def get_monitored_files() -> list[Path]:
    """Return all core files tracked for code integrity."""
    root = config.ROOT
    files = []
    # Studio python files (excluding manifest and pycache)
    studio_dir = root / "studio"
    for p in studio_dir.glob("*.py"):
        files.append(p)
    # Web core files
    web_dir = root / "web"
    for name in ("index.html", "auth.html", "landing.html", "legal.html", "reset.html"):
        p = web_dir / name
        if p.exists():
            files.append(p)
    # Root documentation & license files
    for name in ("LICENSE", "README.md", "AGENTS.md"):
        p = root / name
        if p.exists():
            files.append(p)
    return sorted(files, key=lambda f: str(f))


def compute_manifest_data() -> dict:
    """Build manifest dictionary containing current hashes."""
    root = config.ROOT
    file_map = {}
    for p in get_monitored_files():
        rel = p.relative_to(root).as_posix()
        file_map[rel] = _hash_file(p)
    return {
        "author": AUTHOR,
        "project": PROJECT,
        "sealed_at": time.time(),
        "sealed_by": AUTHOR,
        "file_count": len(file_map),
        "files": file_map,
    }


def seal(pin: str) -> tuple[bool, str]:
    """Seal the codebase with current hashes if PIN is valid."""
    global _is_locked, _tamper_reasons
    if not check_pin(pin):
        return False, "Access Denied: Invalid Security PIN."
    # Check author attribution
    if config.LEGAL_NAME != AUTHOR:
        return False, f"Attribution mismatch: Config author is not '{AUTHOR}'."
    
    data = compute_manifest_data()
    try:
        MANIFEST_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _is_locked = False
        _tamper_reasons = []
        return True, "Security manifest successfully sealed."
    except Exception as e:
        return False, f"Failed to write security manifest: {e}"


def verify() -> tuple[bool, list[str]]:
    """Verify integrity of all monitored files and author attribution."""
    global _is_locked, _tamper_reasons
    
    # Check bypass flag for headless CI/CD if explicitly enabled
    if os.environ.get("QUICKCUTTER_SECURITY_BYPASS") == "1":
        _is_locked = False
        _tamper_reasons = []
        return True, []

    reasons = []
    # Check Author identity in config
    if config.LEGAL_NAME != AUTHOR:
        reasons.append(f"Author identity mismatch in config: Expected '{AUTHOR}', found '{config.LEGAL_NAME}'.")

    if not MANIFEST_PATH.exists():
        reasons.append("Security seal manifest (.security_manifest.json) is missing. Codebase is unsealed.")
    else:
        try:
            data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            if data.get("author") != AUTHOR:
                reasons.append(f"Manifest author tampering detected: Found '{data.get('author')}'.")
            
            saved_files = data.get("files", {})
            current_files = {p.relative_to(config.ROOT).as_posix(): p for p in get_monitored_files()}
            
            # Check for modified or missing files
            for rel_path, expected_hash in saved_files.items():
                p = config.ROOT / rel_path
                if not p.exists():
                    reasons.append(f"Missing protected file: {rel_path}")
                else:
                    curr_hash = _hash_file(p)
                    if curr_hash != expected_hash:
                        reasons.append(f"File modified: {rel_path}")
            
            # Check for unexpected newly injected python files in studio/
            for rel_path in current_files:
                if rel_path not in saved_files:
                    reasons.append(f"Unverified new file detected: {rel_path}")

        except Exception as e:
            reasons.append(f"Failed to read security manifest: {e}")

    if reasons:
        _is_locked = True
        _tamper_reasons = reasons
        return False, reasons
    else:
        _is_locked = False
        _tamper_reasons = []
        return True, []


def is_locked() -> bool:
    """Return whether the application is in tamper lockdown mode."""
    return _is_locked


def get_tamper_reasons() -> list[str]:
    """Return list of detected tampering reasons."""
    return list(_tamper_reasons)


def unlock_and_seal(pin: str) -> tuple[bool, str]:
    """Verify PIN and update the security seal."""
    return seal(pin)


def render_lockdown_html() -> str:
    """Generate high-end branded security lockdown screen."""
    reasons_html = "".join(f"<li>• {r}</li>" for r in _tamper_reasons[:6])
    if len(_tamper_reasons) > 6:
        reasons_html += f"<li>... and {len(_tamper_reasons) - 6} more files.</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Alert · QuickCutter Integrity Shield</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Alex+Brush&family=Montserrat:wght@400;500;600;700&family=Playfair+Display:ital,wght@0,600;0,700;1,600&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: radial-gradient(ellipse at 50% 30%, #2a080c 0%, #150305 60%, #0a0102 100%);
      color: #FFF0DC;
      font-family: 'Montserrat', sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      overflow-x: hidden;
    }}
    .shield-card {{
      background: rgba(30, 8, 11, 0.85);
      border: 1px solid rgba(212, 175, 55, 0.35);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7), 0 0 40px rgba(121, 11, 19, 0.35);
      border-radius: 20px;
      max-width: 560px;
      width: 100%;
      padding: 44px 38px;
      text-align: center;
      position: relative;
    }}
    .shield-badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 16px;
      border-radius: 999px;
      background: rgba(220, 38, 38, 0.18);
      border: 1px solid rgba(239, 68, 68, 0.45);
      color: #fca5a5;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      margin-bottom: 22px;
    }}
    .shield-icon {{
      font-size: 46px;
      line-height: 1;
      margin-bottom: 12px;
      filter: drop-shadow(0 0 16px rgba(239, 68, 68, 0.6));
    }}
    h1 {{
      font-family: 'Playfair Display', serif;
      font-size: 28px;
      font-weight: 700;
      color: #FFF0DC;
      margin-bottom: 8px;
      letter-spacing: -0.5px;
    }}
    .author-lockup {{
      font-family: 'Alex Brush', cursive;
      font-size: 26px;
      color: #E8B4B8;
      margin-bottom: 18px;
      display: block;
      letter-spacing: 0.5px;
    }}
    p.desc {{
      font-size: 13.5px;
      line-height: 1.6;
      color: rgba(255, 240, 220, 0.82);
      margin-bottom: 22px;
    }}
    .tamper-box {{
      background: rgba(15, 3, 5, 0.75);
      border: 1px solid rgba(220, 38, 38, 0.25);
      border-radius: 10px;
      padding: 12px 16px;
      text-align: left;
      font-size: 11.5px;
      font-family: monospace;
      color: #fca5a5;
      margin-bottom: 26px;
      max-height: 120px;
      overflow-y: auto;
    }}
    .tamper-box ul {{
      list-style: none;
      padding: 0;
      margin: 0;
    }}
    .tamper-box li {{
      margin-bottom: 4px;
      word-break: break-all;
    }}
    .pin-form {{
      display: flex;
      flex-direction: column;
      gap: 14px;
      align-items: center;
    }}
    .pin-input {{
      width: 100%;
      max-width: 280px;
      background: rgba(15, 3, 5, 0.8);
      border: 1px solid rgba(212, 175, 55, 0.4);
      color: #FFF0DC;
      font-size: 22px;
      letter-spacing: 8px;
      text-align: center;
      padding: 12px 16px;
      border-radius: 10px;
      outline: none;
      transition: all 0.2s ease;
      font-family: monospace;
    }}
    .pin-input:focus {{
      border-color: #D4AF37;
      box-shadow: 0 0 16px rgba(212, 175, 55, 0.35);
    }}
    .btn-unlock {{
      background: linear-gradient(135deg, #790B13 0%, #a8131d 100%);
      color: #FFF0DC;
      border: 1px solid rgba(212, 175, 55, 0.4);
      font-family: 'Montserrat', sans-serif;
      font-weight: 600;
      font-size: 14px;
      letter-spacing: 0.5px;
      padding: 13px 32px;
      border-radius: 10px;
      cursor: pointer;
      width: 100%;
      max-width: 280px;
      transition: all 0.25s ease;
      box-shadow: 0 8px 20px rgba(121, 11, 19, 0.4);
    }}
    .btn-unlock:hover {{
      background: linear-gradient(135deg, #93131D 0%, #bf1925 100%);
      border-color: #D4AF37;
      transform: translateY(-1px);
      box-shadow: 0 10px 24px rgba(121, 11, 19, 0.6);
    }}
    .status-msg {{
      font-size: 12.5px;
      margin-top: 10px;
      min-height: 20px;
      transition: all 0.2s ease;
    }}
    .status-msg.error {{ color: #ef4444; }}
    .status-msg.success {{ color: #10b981; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="shield-card">
    <div class="shield-icon">🔒</div>
    <div class="shield-badge">Tamper Alert · Code Integrity Violation</div>
    <h1>QuickCutter Security Shield</h1>
    <span class="author-lockup">by Anurag Sharma</span>
    <p class="desc">
      Project files or author identity attribution have been modified without authorization.
      To protect this application and verify developer ownership, enter the <strong>Developer Master Security PIN</strong>.
    </p>

    <div class="tamper-box">
      <ul>{reasons_html}</ul>
    </div>

    <form class="pin-form" id="unlockForm" onsubmit="handleUnlock(event)">
      <input type="password" id="pinInput" class="pin-input" placeholder="••••••" maxlength="12" autofocus autocomplete="off" />
      <button type="submit" class="btn-unlock" id="unlockBtn">Verify & Unlock System</button>
      <div id="statusMsg" class="status-msg"></div>
    </form>
  </div>

  <script>
    async function handleUnlock(e) {{
      e.preventDefault();
      const pin = document.getElementById('pinInput').value.trim();
      const msg = document.getElementById('statusMsg');
      const btn = document.getElementById('unlockBtn');
      if (!pin) {{
        msg.className = 'status-msg error';
        msg.innerText = 'Please enter the master security PIN.';
        return;
      }}
      btn.disabled = true;
      btn.innerText = 'Verifying PIN...';
      msg.innerText = '';
      try {{
        const res = await fetch('/api/security/unlock', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ pin: pin }})
        }});
        const data = await res.json();
        if (res.ok && data.ok) {{
          msg.className = 'status-msg success';
          msg.innerText = '✓ Security PIN Verified! System unsealed for Anurag Sharma. Reloading...';
          setTimeout(() => {{ window.location.href = '/app'; }}, 1200);
        }} else {{
          msg.className = 'status-msg error';
          msg.innerText = '❌ Access Denied: ' + (data.detail || 'Incorrect security PIN.');
          btn.disabled = false;
          btn.innerText = 'Verify & Unlock System';
        }}
      }} catch (err) {{
        msg.className = 'status-msg error';
        msg.innerText = 'Server error during verification.';
        btn.disabled = false;
        btn.innerText = 'Verify & Unlock System';
      }}
    }}
  </script>
</body>
</html>
"""


# CLI Support for sealing and checking
if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "seal":
        pin = sys.argv[2] if len(sys.argv) > 2 else input("Enter Master Security PIN: ")
        ok, msg = seal(pin)
        print(f"[{'OK' if ok else 'FAIL'}] {msg}")
        sys.exit(0 if ok else 1)
    elif action == "check":
        ok, reasons = verify()
        if ok:
            print(f"[OK] QuickCutter code integrity intact. Author: {AUTHOR}")
            sys.exit(0)
        else:
            print(f"[FAIL] Codebase integrity check failed ({len(reasons)} issues detected):")
            for r in reasons:
                print(f"  • {r}")
            sys.exit(1)
    else:
        print("Usage: python -m studio.security [check|seal <pin>]")
        sys.exit(1)
