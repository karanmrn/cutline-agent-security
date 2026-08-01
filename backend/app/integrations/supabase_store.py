from __future__ import annotations

import os
from typing import Any


class SupabaseMirror:
    def __init__(self) -> None:
        self.url = os.getenv("SUPABASE_URL")
        self.key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self.client: Any | None = None
        self.error: str | None = None

        if self.url and self.key:
            try:
                from supabase import create_client

                self.client = create_client(self.url, self.key)
            except Exception as exc:  # pragma: no cover - optional integration
                self.error = str(exc)

    @property
    def enabled(self) -> bool:
        return self.client is not None

    def insert(self, table: str, row: dict[str, Any]) -> None:
        if not self.client:
            return
        try:
            self.client.table(table).insert(row).execute()
        except Exception as exc:  # pragma: no cover - optional integration
            self.error = str(exc)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "configured": bool(self.url and self.key),
            "error": self.error,
        }


mirror = SupabaseMirror()
