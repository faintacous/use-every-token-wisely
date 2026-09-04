"""Kimi (Moonshot AI) usage provider — reads real quota from the Kimi APIs.

Three credential sources, tried in order:

1. **API key** (``kimi_api_key`` in ``config.json``) — a Kimi Code Console
   API key used directly as the Bearer token. Stateless: no refresh, no
   write-back, no token-rotation races::

       GET https://api.kimi.com/coding/v1/usages
       Authorization: Bearer <api_key>

2. **Kimi Code CLI** (``$KIMI_CODE_HOME/credentials/kimi-code.json``, default
   ``~/.kimi-code/credentials/kimi-code.json``) — OAuth tokens for the Kimi
   for Coding plan, shared with the new Kimi Code CLI; the legacy Python
   kimi-cli location (``~/.kimi/credentials/kimi-code.json``) is the fallback.
   Quota comes from the same endpoint the CLI's own ``/usage`` command calls::

       GET https://api.kimi.com/coding/v1/usages
       Authorization: Bearer <access_token>

   Access tokens are short-lived, so expired ones are refreshed via
   ``POST https://auth.kimi.com/api/oauth/token`` (standard OAuth2 refresh,
   client_id replicated from the CLI source) and written back atomically.
   Concurrent refreshes are serialized with a lock file next to the
   credentials (``kimi-code.lock``, msvcrt.locking / fcntl.flock).

3. **Kimi desktop app** (``AppData/Roaming/kimi-desktop/bridge-store/``) —
   the original implementation, calling the consumer membership API::

       POST https://www.kimi.com/apiv2/kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.request
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from .base import BaseProvider, UsageData, WindowStats

# --- Kimi CLI (Kimi for Coding) -------------------------------------------

def _kimi_code_home() -> Path:
    """Data root of the new Kimi Code CLI: $KIMI_CODE_HOME or ~/.kimi-code."""
    env = os.environ.get("KIMI_CODE_HOME")
    return Path(env) if env else _home() / ".kimi-code"


def _legacy_cli_home() -> Path:
    """Data root of the legacy Python kimi-cli."""
    return _home() / ".kimi"


def _cli_credentials_candidates() -> list[Path]:
    """Credentials files in preference order: new Kimi Code CLI, then legacy."""
    return [
        _kimi_code_home() / "credentials" / "kimi-code.json",
        _legacy_cli_home() / "credentials" / "kimi-code.json",
    ]


def _cli_device_id_candidates() -> list[Path]:
    """device_id files in the same preference order as the credentials."""
    return [
        _kimi_code_home() / "device_id",
        _legacy_cli_home() / "device_id",
    ]


CLI_USAGES_URL = "https://api.kimi.com/coding/v1/usages"
CLI_TOKEN_URL = "https://auth.kimi.com/api/oauth/token"
#: Public OAuth client_id, replicated from kimi_cli/auth/oauth.py.
CLI_CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098"
#: Refresh when the token expires within this many seconds.
CLI_REFRESH_MARGIN_SECONDS = 300

# --- Kimi desktop app ------------------------------------------------------

DESKTOP_TOKEN_PATH = (
    Path(os.path.expanduser("~"))
    / "AppData" / "Roaming" / "kimi-desktop" / "bridge-store" / "token-store.json"
)
DESKTOP_IDENTITY_PATH = Path(os.path.expanduser("~")) / ".kimi-webbridge" / "identity.json"
DESKTOP_STATS_URL = (
    "https://www.kimi.com/apiv2/"
    "kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats"
)


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def _parse_iso(raw) -> datetime | None:
    """Parse ISO-8601, tolerating nanosecond fractions (truncate to µs)."""
    if not raw:
        return None
    try:
        s = str(raw).strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # fromisoformat caps at microseconds; trim longer fractions.
        if "." in s:
            head, tail = s.split(".", 1)
            frac, _, offset = tail.partition("+")
            if not offset:
                frac, _, offset = tail.partition("-")
                offset = ("-" + offset) if offset else ""
            else:
                offset = "+" + offset
            if len(frac) > 6:
                s = f"{head}.{frac[:6]}{offset}"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class _CredentialsLock:
    """File lock serializing credential refreshes across processes.

    One byte at position 0 of ``kimi-code.lock`` (next to the credentials
    file) via ``msvcrt.locking`` (Windows) or ``fcntl.flock``. Mirrors the
    legacy kimi-cli's own locking; the new Kimi Code CLI writes credentials
    atomically without a lock, so there it only guards this app's instances.
    """

    def __init__(self, path: Path):
        self._path = path
        self._fd: int | None = None

    def acquire(self, retries: int = 5, delay: float = 0.2) -> bool:
        for attempt in range(retries):
            try:
                self._fd = os.open(str(self._path), os.O_RDWR | os.O_CREAT)
                if sys.platform == "win32":
                    import msvcrt

                    # msvcrt.locking requires a byte to exist at the lock position.
                    if os.path.getsize(self._path) == 0:
                        os.write(self._fd, b"\0")
                        os.lseek(self._fd, 0, os.SEEK_SET)
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if self._fd is not None:
                    with suppress(OSError):
                        os.close(self._fd)
                    self._fd = None
                if attempt < retries - 1:
                    time.sleep(delay)
        return False

    def release(self) -> None:
        if self._fd is None:
            return
        with suppress(OSError):
            if sys.platform == "win32":
                import msvcrt

                os.lseek(self._fd, 0, os.SEEK_SET)
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(self._fd)
        self._fd = None

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *args: object) -> None:
        self.release()


class KimiProvider(BaseProvider):
    """Reads real Kimi usage via the CLI (Kimi for Coding) or desktop app."""

    # Budgets are nominal — the API reports real request counts / percentages.
    default_budget_5h = 100
    default_budget_7d = 100

    def __init__(
        self,
        budget_5h: int | None = None,
        budget_7d: int | None = None,
        api_key: str | None = None,
    ):
        super().__init__(budget_5h, budget_7d)
        self._api_key = (api_key or "").strip() or None

    # ------------------------------------------------------------------
    # Kimi CLI credentials
    # ------------------------------------------------------------------

    @staticmethod
    def _read_credentials_file(path: Path) -> dict | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        return data if isinstance(data, dict) and data.get("access_token") else None

    def _load_cli_credentials(self) -> tuple[Path, dict] | None:
        """First usable (path, credentials) among the known CLI locations."""
        for path in _cli_credentials_candidates():
            if not path.exists():
                continue
            creds = self._read_credentials_file(path)
            if creds:
                return path, creds
        return None

    def _save_cli_credentials(self, path: Path, creds: dict) -> None:
        """Atomic write, same pattern as the CLI (temp file + os.replace)."""
        fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            data = json.dumps(creds, ensure_ascii=False).encode("utf-8")
            if os.write(fd, data) != len(data):
                raise OSError("Short write to credentials temp file")
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp_path, path)
        except BaseException:
            if fd >= 0:
                with suppress(OSError):
                    os.close(fd)
            with suppress(OSError):
                os.unlink(tmp_path)
            raise

    def _cli_common_headers(self) -> dict[str, str]:
        """Subset of the CLI's X-Msh-* headers, for the refresh request."""
        headers = {"X-Msh-Platform": "kimi_cli"}
        try:
            for path in _cli_device_id_candidates():
                if path.exists():
                    headers["X-Msh-Device-Id"] = path.read_text(
                        encoding="utf-8"
                    ).strip()
                    break
        except OSError:
            pass
        try:
            headers["X-Msh-Device-Name"] = socket.gethostname()
        except OSError:
            pass
        return headers

    def _refresh_cli_token(self, refresh_token: str) -> dict | None:
        """Exchange a refresh token for new tokens via the CLI's OAuth host."""
        body = urlencode({
            "client_id": CLI_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }).encode("utf-8")
        req = urllib.request.Request(CLI_TOKEN_URL, data=body, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        for key, value in self._cli_common_headers().items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
            return None
        return data if isinstance(data, dict) and data.get("access_token") else None

    def _cli_access_token(self, force_refresh: bool = False) -> str | None:
        """Return a valid CLI access token, refreshing + writing back if needed."""
        loaded = self._load_cli_credentials()
        if not loaded:
            return None
        path, creds = loaded

        expires_at = float(creds.get("expires_at") or 0)
        if not force_refresh and time.time() < expires_at - CLI_REFRESH_MARGIN_SECONDS:
            return creds["access_token"]

        if not creds.get("refresh_token"):
            return None

        # Serialize against other refreshes of the same credentials file.
        lock = _CredentialsLock(path.with_suffix(".lock"))
        locked = lock.acquire()
        try:
            if locked:
                # Another process may have refreshed while we waited.
                fresh = self._read_credentials_file(path)
                if fresh:
                    creds = fresh
                expires_at = float(creds.get("expires_at") or 0)
                if not force_refresh and time.time() < expires_at - CLI_REFRESH_MARGIN_SECONDS:
                    return creds["access_token"]

            new = self._refresh_cli_token(creds["refresh_token"])
            if not new:
                return None
            creds.update({
                "access_token": new["access_token"],
                "refresh_token": new.get("refresh_token") or creds["refresh_token"],
                "expires_in": float(new.get("expires_in") or 0),
                "expires_at": time.time() + float(new.get("expires_in") or 0),
                "scope": new.get("scope") or creds.get("scope", ""),
                "token_type": new.get("token_type") or creds.get("token_type", ""),
            })
            try:
                self._save_cli_credentials(path, creds)
            except OSError:
                pass  # Token is still usable in-memory for this fetch.
            return creds["access_token"]
        finally:
            if locked:
                lock.release()

    def _fetch_apikey_usages(self) -> dict | None:
        """Call the usages endpoint with a Console API key (no refresh dance)."""
        req = urllib.request.Request(CLI_USAGES_URL)
        req.add_header("Authorization", f"Bearer {self._api_key}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
            return None

    def _fetch_cli_usages(self) -> dict | None:
        """Call the Kimi for Coding usages endpoint (one forced refresh on 401)."""
        force_refresh = False
        for attempt in range(2):
            token = self._cli_access_token(force_refresh=force_refresh)
            if not token:
                return None
            req = urllib.request.Request(CLI_USAGES_URL)
            req.add_header("Authorization", f"Bearer {token}")
            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    # Token was rejected despite looking fresh — rotate it.
                    force_refresh = True
                    continue
                return None
            except (urllib.error.URLError, OSError, ValueError):
                return None
        return None

    # ------------------------------------------------------------------
    # Kimi desktop app credentials (original implementation)
    # ------------------------------------------------------------------

    def _load_desktop_token(self) -> tuple[str | None, str | None]:
        """Return (access_token, device_id) from the desktop app's files.

        The desktop app recently started encrypting its token store with
        Electron's safeStorage (Chromium os_crypt: DPAPI + AES-256-GCM).
        We handle both the legacy plaintext and the encrypted format.
        """
        if not DESKTOP_TOKEN_PATH.exists():
            return None, None
        try:
            store = json.loads(DESKTOP_TOKEN_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None, None

        token = store.get("tokens", {}).get("access_token")
        if not token and store.get("encryption") == "safeStorage.v1":
            token = self._decrypt_safe_storage(store.get("data"))

        device_id = None
        if DESKTOP_IDENTITY_PATH.exists():
            try:
                device_id = json.loads(
                    DESKTOP_IDENTITY_PATH.read_text(encoding="utf-8")
                ).get("device_id")
            except (json.JSONDecodeError, OSError):
                pass
        return token, device_id

    @staticmethod
    def _decrypt_safe_storage(enc_b64: str) -> str | None:
        """Decrypt an Electron safeStorage v10 blob (Windows).

        Same mechanism as Chromium os_crypt: the AES-256 key is wrapped by
        Windows DPAPI in the app's Local State; the blob itself is
        'v10' + 12-byte nonce + ciphertext + 16-byte GCM tag.
        """
        if sys.platform != "win32" or not enc_b64:
            return None
        try:
            import base64
            import ctypes
            import ctypes.wintypes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            app_dir = DESKTOP_TOKEN_PATH.parent.parent
            ls = json.loads(
                (app_dir / "Local State").read_text(encoding="utf-8")
            )
            key_b64 = ls.get("os_crypt", {}).get("encrypted_key", "")
            if not key_b64:
                return None
            enc_key = base64.b64decode(key_b64)
            if not enc_key.startswith(b"DPAPI"):
                return None

            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ("cbData", ctypes.wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char)),
                ]

            blob_in = DATA_BLOB(
                len(enc_key) - 5,
                ctypes.cast(
                    ctypes.create_string_buffer(enc_key[5:], len(enc_key) - 5),
                    ctypes.POINTER(ctypes.c_char),
                ),
            )
            blob_out = DATA_BLOB()
            if not ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0,
                ctypes.byref(blob_out),
            ):
                return None
            aes_key = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)

            blob = base64.b64decode(enc_b64)
            if not blob.startswith(b"v10"):
                return None
            nonce = blob[3:15]
            ciphertext = blob[15:]
            plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
            store = json.loads(plaintext.decode("utf-8"))
            return store.get("tokens", {}).get("access_token")
        except Exception:
            return None

    def _fetch_desktop_stats(self) -> dict | None:
        token, device_id = self._load_desktop_token()
        if not token:
            return None

        req = urllib.request.Request(DESKTOP_STATS_URL, data=b"{}", method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json")
        req.add_header("connect-protocol-version", "1")
        req.add_header("r-timezone", "Asia/Taipei")
        req.add_header("x-msh-platform", "windows")
        if device_id:
            req.add_header("x-msh-device-id", device_id)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    @staticmethod
    def _count_window(label: str, detail: dict) -> WindowStats | None:
        """Build a WindowStats from a {limit, used?, remaining?, resetTime} dict.

        The API returns either ``used`` or ``remaining`` — compute whichever
        is missing from the limit.
        """
        try:
            limit = int(detail.get("limit") or 0)
        except (TypeError, ValueError):
            return None
        if limit <= 0:
            return None
        if detail.get("used") is not None:
            try:
                used = int(detail.get("used") or 0)
            except (TypeError, ValueError):
                return None
        elif detail.get("remaining") is not None:
            try:
                remaining = int(detail.get("remaining") or 0)
            except (TypeError, ValueError):
                return None
            used = max(0, limit - remaining)
        else:
            return None
        return WindowStats(
            label=label,
            percent=used / limit * 100,
            budget=limit,
            used=used,
            reset_at=_parse_iso(detail.get("resetTime")),
            is_real_limit=True,
        )

    def fetch(self) -> UsageData:
        # API key first: stateless, no refresh, no credential file touched.
        if self._api_key:
            payload = self._fetch_apikey_usages()
            if payload is not None:
                return self._build_cli_usage(payload)

        payload = self._fetch_cli_usages()
        if payload is not None:
            return self._build_cli_usage(payload)

        data = self._build_desktop_usage()
        if data is not None:
            return data

        data = UsageData(service="Kimi")
        data.available = False
        data.error = "Cannot reach Kimi API"
        return data

    def _build_cli_usage(self, payload: dict) -> UsageData:
        data = UsageData(service="Kimi")

        # Weekly quota (request count) → 7d bar (used = limit - remaining).
        weekly = payload.get("usage") or {}
        w7 = self._count_window("7d", weekly)
        if w7:
            data.window_7d = w7

        # Short rate-limit window (300 minutes = 5h).
        for entry in payload.get("limits") or []:
            window = entry.get("window") or {}
            if (
                window.get("duration") == 300
                and window.get("timeUnit") == "TIME_UNIT_MINUTE"
            ):
                w5 = self._count_window("5h", entry.get("detail") or {})
                if w5:
                    data.window_5h = w5
                break

        # Membership tier, e.g. "LEVEL_INTERMEDIATE" → "Intermediate".
        level = ((payload.get("user") or {}).get("membership") or {}).get("level", "")
        if isinstance(level, str) and level.startswith("LEVEL_"):
            data.plan_type = level.removeprefix("LEVEL_").replace("_", " ").title()
        elif level:
            data.plan_type = str(level)

        # The coding usages API exposes no monthly total (totalQuota stays
        # empty for coding plans) — supplement it from the desktop membership
        # API when the desktop app credentials are available.
        desktop = self._fetch_desktop_stats()
        if desktop is not None:
            total = self._total_window(desktop)
            if total is not None:
                data.extra_windows.append(total)

            # If monthly quota exhausted, 5h/7d show as fully used (empty bars).
            is_exhausted = desktop.get("overdrawn") or (
                total is not None and total.percent >= 100
            )
            window_pct = 100.0 if is_exhausted else 0.0

            # Only add desktop 5h/7d if the CLI didn't already fill them.
            rl5h = desktop.get("ratelimitCode5h") or {}
            if rl5h.get("enabled") and data.window_5h.reset_at is None:
                data.extra_windows.append(WindowStats(
                    label="5h",
                    percent=window_pct,
                    reset_at=_parse_iso(rl5h.get("resetTime")),
                    is_real_limit=is_exhausted,
                ))
            rl7d = desktop.get("ratelimitCode7d") or {}
            if rl7d.get("enabled") and data.window_7d.reset_at is None:
                data.extra_windows.append(WindowStats(
                    label="7d",
                    percent=window_pct,
                    reset_at=_parse_iso(rl7d.get("resetTime")),
                    is_real_limit=is_exhausted,
                ))

            self._apply_overdrawn(data, desktop)

        return data

    @staticmethod
    def _total_window(payload: dict) -> WindowStats | None:
        """Monthly membership usage → the 'Total' window (desktop API only)."""
        balance = payload.get("subscriptionBalance") or {}
        if balance.get("amountUsedRatio") is None:
            return None
        used_pct = float(balance.get("amountUsedRatio")) * 100
        return WindowStats(
            label="Total",
            percent=used_pct,
            budget=100,
            used=int(round(used_pct)),
            reset_at=_parse_iso(balance.get("expireTime")),
            is_real_limit=True,
        )

    @staticmethod
    def _apply_overdrawn(data: UsageData, payload: dict) -> None:
        if payload.get("overdrawn"):
            data.plan_type = (
                f"{data.plan_type} | Overdrawn" if data.plan_type else "Overdrawn"
            )

    def _build_desktop_usage(self) -> UsageData | None:
        payload = self._fetch_desktop_stats()
        if payload is None:
            return None

        data = UsageData(service="Kimi")

        # Total monthly usage (resets at expireTime, e.g. monthly)
        # This is the only real usage percentage the API provides.
        total = self._total_window(payload)
        if total is not None:
            data.extra_windows.append(total)

        # 5h and 7d: if monthly quota is exhausted, show as fully used
        # (empty bars). Otherwise show as info-only (no independent usage).
        is_exhausted = payload.get("overdrawn") or (
            total is not None and total.percent >= 100
        )
        window_pct = 100.0 if is_exhausted else 0.0

        rl5h = payload.get("ratelimitCode5h") or {}
        if rl5h.get("enabled"):
            data.extra_windows.append(WindowStats(
                label="5h",
                percent=window_pct,
                budget=100,
                used=int(round(window_pct)),
                reset_at=_parse_iso(rl5h.get("resetTime")),
                is_real_limit=is_exhausted,
            ))

        rl7d = payload.get("ratelimitCode7d") or {}
        if rl7d.get("enabled"):
            data.extra_windows.append(WindowStats(
                label="7d",
                percent=window_pct,
                budget=100,
                used=int(round(window_pct)),
                reset_at=_parse_iso(rl7d.get("resetTime")),
                is_real_limit=is_exhausted,
            ))

        sub_data = ""
        try:
            store = json.loads(DESKTOP_TOKEN_PATH.read_text(encoding="utf-8"))
            sub_data = store.get("tokens", {}).get("msh_user_subscription_data", "")
            if isinstance(sub_data, str):
                sub_data = json.loads(sub_data).get("currentMembershipLevel", "")
        except Exception:
            pass
        if sub_data == 25:
            data.plan_type = "Pro"
        elif sub_data == 10:
            data.plan_type = "Plus"
        else:
            data.plan_type = str(sub_data) if sub_data else ""

        self._apply_overdrawn(data, payload)

        return data
