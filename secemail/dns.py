"""DNS resolver using dnspython with a ``dig`` fallback."""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import List, Tuple


class DnsResolverError(RuntimeError):
    pass


class DnsResolver:
    """Resolve TXT/CNAME/MX using dnspython if available, or dig as a fallback."""

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout
        self._dns = None
        self._dig_path = shutil.which("dig")
        self.backend = ""
        self.errors: List[str] = []
        self._seen_errors = set()
        try:
            import dns.resolver  # type: ignore

            self._dns = dns.resolver
        except Exception:
            self._dns = None

        if self._dns:
            self.backend = "dnspython"
        elif self._dig_path:
            self.backend = "dig"
        else:
            raise DnsResolverError(
                "No DNS resolver available: install dnspython or ensure 'dig' is on PATH."
            )

    def _record_error(self, message: str) -> None:
        if message in self._seen_errors:
            return
        self._seen_errors.add(message)
        self.errors.append(message)

    @staticmethod
    def _is_expected_empty_answer(exc: Exception) -> bool:
        name = exc.__class__.__name__.lower()
        return name in {"nxdomain", "noanswer", "nodata"}

    def txt(self, name: str) -> List[str]:
        if self._dns:
            records = self._txt_dnspython(name)
            if records or not self._dig_path:
                return records
        return self._txt_dig(name)

    def cname(self, name: str) -> List[str]:
        if self._dns:
            records = self._cname_dnspython(name)
            if records or not self._dig_path:
                return records
        return self._cname_dig(name)

    def _txt_dnspython(self, name: str) -> List[str]:
        records: List[str] = []
        try:
            resolver = self._dns.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, "TXT")
            for answer in answers:
                if hasattr(answer, "strings"):
                    value = b"".join(answer.strings).decode("utf-8", errors="replace")
                else:
                    value = str(answer).strip('"')
                if value:
                    records.append(value)
        except Exception as exc:
            if not self._is_expected_empty_answer(exc):
                self._record_error(f"DNS TXT error ({name}) via dnspython: {exc}")
            return []
        return records

    def _cname_dnspython(self, name: str) -> List[str]:
        records: List[str] = []
        try:
            resolver = self._dns.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, "CNAME")
            for answer in answers:
                value = str(answer).rstrip(".")
                if value:
                    records.append(value)
        except Exception as exc:
            if not self._is_expected_empty_answer(exc):
                self._record_error(f"DNS CNAME error ({name}) via dnspython: {exc}")
            return []
        return records

    def _txt_dig(self, name: str) -> List[str]:
        cmd = [self._dig_path or "dig", "+time=2", "+tries=1", "+short", "TXT", name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 1)
        except Exception as exc:
            self._record_error(f"Error running dig TXT ({name}): {exc}")
            return []
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            self._record_error(f"dig TXT returned code {proc.returncode} for {name}. {stderr}".strip())
            return []

        values: List[str] = []
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = re.findall(r'"([^"]*)"', line)
            if parts:
                values.append("".join(parts))
            else:
                values.append(line.strip('"'))
        return values

    def _cname_dig(self, name: str) -> List[str]:
        cmd = [self._dig_path or "dig", "+time=2", "+tries=1", "+short", "CNAME", name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 1)
        except Exception as exc:
            self._record_error(f"Error running dig CNAME ({name}): {exc}")
            return []
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            self._record_error(f"dig CNAME returned code {proc.returncode} for {name}. {stderr}".strip())
            return []

        values: List[str] = []
        for raw_line in proc.stdout.splitlines():
            line = raw_line.strip().rstrip(".")
            if line:
                values.append(line)
        return values

    def mx(self, name: str) -> List[Tuple[int, str]]:
        if self._dns:
            records = self._mx_dnspython(name)
            if records or not self._dig_path:
                return records
        return self._mx_dig(name)

    def _mx_dnspython(self, name: str) -> List[Tuple[int, str]]:
        records: List[Tuple[int, str]] = []
        try:
            resolver = self._dns.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, "MX")
            for answer in answers:
                records.append((answer.preference, str(answer.exchange).rstrip(".")))
        except Exception as exc:
            if not self._is_expected_empty_answer(exc):
                self._record_error(f"DNS MX error ({name}) via dnspython: {exc}")
            return []
        return records

    def _mx_dig(self, name: str) -> List[Tuple[int, str]]:
        cmd = [self._dig_path or "dig", "+time=2", "+tries=1", "+short", "MX", name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 1)
        except Exception as exc:
            self._record_error(f"Error running dig MX ({name}): {exc}")
            return []
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            self._record_error(f"dig MX returned code {proc.returncode} for {name}. {stderr}".strip())
            return []

        values: List[Tuple[int, str]] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) == 2:
                try:
                    pref = int(parts[0])
                    host = parts[1].rstrip(".")
                    values.append((pref, host))
                except ValueError:
                    pass
        return values

    def tlsa(self, name: str) -> List[Tuple[int, int, int, str]]:
        """Resolve TLSA (RFC 6698). Returns a list of (usage, selector, mtype, hex_data)."""
        if self._dns:
            records = self._tlsa_dnspython(name)
            if records or not self._dig_path:
                return records
        return self._tlsa_dig(name)

    def _tlsa_dnspython(self, name: str) -> List[Tuple[int, int, int, str]]:
        records: List[Tuple[int, int, int, str]] = []
        try:
            resolver = self._dns.Resolver()  # type: ignore[attr-defined]
            resolver.lifetime = self.timeout
            answers = resolver.resolve(name, "TLSA")
            for answer in answers:
                try:
                    usage = int(getattr(answer, "usage"))
                    selector = int(getattr(answer, "selector"))
                    mtype = int(getattr(answer, "mtype"))
                    cert = getattr(answer, "cert", b"")
                    hex_data = cert.hex() if isinstance(cert, (bytes, bytearray)) else str(cert)
                    records.append((usage, selector, mtype, hex_data))
                except Exception:
                    text = str(answer).split()
                    if len(text) >= 4:
                        try:
                            records.append(
                                (int(text[0]), int(text[1]), int(text[2]), " ".join(text[3:]))
                            )
                        except ValueError:
                            continue
        except Exception as exc:
            if not self._is_expected_empty_answer(exc):
                self._record_error(f"DNS TLSA error ({name}) via dnspython: {exc}")
            return []
        return records

    def _tlsa_dig(self, name: str) -> List[Tuple[int, int, int, str]]:
        cmd = [self._dig_path or "dig", "+time=2", "+tries=1", "+short", "TLSA", name]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 1)
        except Exception as exc:
            self._record_error(f"Error running dig TLSA ({name}): {exc}")
            return []
        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            self._record_error(f"dig TLSA returned code {proc.returncode} for {name}. {stderr}".strip())
            return []

        values: List[Tuple[int, int, int, str]] = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            try:
                values.append(
                    (int(parts[0]), int(parts[1]), int(parts[2]), " ".join(parts[3:]))
                )
            except ValueError:
                continue
        return values
