# SPDX-FileCopyrightText: 2026 Mohsen Bah
# SPDX-License-Identifier: Apache-2.0
"""Hold back SSE events until a secret scan says they are safe to send."""

from __future__ import annotations

from app.scanners.secrets import ScanResult, SecretScanner, extract_completion_text

# Long enough that an AWS key, GitHub token, or PEM header split across
# events is scanned before any of those bytes are released.
HOLDBACK_CHARS = 128


class SseSecretGate:
    """Release SSE events only after later text has been scanned clean.

    A secret that completes in a later event is not included in the released
    bytes. ``blocked`` is set on the first match.
    """

    def __init__(self, scanner: SecretScanner) -> None:
        self._scanner = scanner
        self._raw = bytearray()
        self._pending: list[tuple[bytes, int]] = []
        self._text = ""
        self.blocked = False
        self.scan_result = ScanResult(contains_secret=False)

    @property
    def text(self) -> str:
        return self._text

    def feed(self, chunk: bytes) -> list[bytes]:
        if self.blocked or not chunk:
            return []
        self._raw.extend(chunk)
        released: list[bytes] = []
        while not self.blocked:
            sep = self._raw.find(b"\n\n")
            if sep < 0:
                break
            event = bytes(self._raw[: sep + 2])
            del self._raw[: sep + 2]
            self._accept(event, released)
        return released

    def finish(self) -> list[bytes]:
        """Stream ended. Release the holdback, or drop it if it holds a secret."""
        if self.blocked:
            return []
        released: list[bytes] = []
        if self._raw:
            event = bytes(self._raw)
            self._raw.clear()
            self._accept(event, released)
        if self.blocked:
            return released
        released.extend(event for event, _end in self._pending)
        self._pending.clear()
        return released

    def _accept(self, event: bytes, released: list[bytes]) -> None:
        self._text += extract_completion_text(event)
        self._pending.append((event, len(self._text)))
        result = self._scanner.scan(self._text)
        if result.contains_secret:
            self.blocked = True
            self.scan_result = result
            self._pending.clear()
            self._raw.clear()
            return
        released.extend(self._release_safe())

    def _release_safe(self) -> list[bytes]:
        cutoff = len(self._text) - HOLDBACK_CHARS
        out: list[bytes] = []
        while self._pending and self._pending[0][1] <= cutoff:
            out.append(self._pending.pop(0)[0])
        return out
