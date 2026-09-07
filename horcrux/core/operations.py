from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class OperationStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


@dataclass
class OperationState:
    name: str
    target: str = ""
    phase: str = ""
    status: OperationStatus = OperationStatus.PENDING
    progress_pct: Optional[float] = None
    started_at: float = field(default_factory=time.monotonic)
    ended_at: Optional[float] = None
    message: str = ""
    current_item: str = ""
    total_items: int = 0
    completed_items: int = 0
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        end = self.ended_at or time.monotonic()
        return max(0.0, end - self.started_at)

    def start(self, phase: str = "", total_items: int = 0) -> None:
        self.status = OperationStatus.RUNNING
        self.started_at = time.monotonic()
        self.ended_at = None
        self.phase = phase
        self.total_items = total_items
        self.completed_items = 0

    def update(
        self,
        phase: Optional[str] = None,
        current_item: Optional[str] = None,
        progress_pct: Optional[float] = None,
        message: Optional[str] = None,
        completed_delta: int = 0,
    ) -> None:
        if phase is not None:
            self.phase = phase
        if current_item is not None:
            self.current_item = current_item
        if message is not None:
            self.message = message
        self.completed_items += completed_delta
        if progress_pct is not None:
            self.progress_pct = max(0.0, min(100.0, progress_pct))
        elif self.total_items > 0:
            self.progress_pct = round((self.completed_items / self.total_items) * 100.0, 1)

    def complete(self, message: str = "") -> None:
        self.status = OperationStatus.COMPLETED
        self.ended_at = time.monotonic()
        self.progress_pct = 100.0
        if message:
            self.message = message

    def complete_partial(self, message: str = "", error: str = "") -> None:
        self.status = OperationStatus.PARTIAL
        self.ended_at = time.monotonic()
        if message:
            self.message = message
        if error:
            self.error = error

    def fail(self, error: str) -> None:
        self.status = OperationStatus.FAILED
        self.ended_at = time.monotonic()
        self.error = error

    def cancel(self, reason: str = "Operation cancelled by operator") -> None:
        self.status = OperationStatus.CANCELLED
        self.ended_at = time.monotonic()
        self.message = reason