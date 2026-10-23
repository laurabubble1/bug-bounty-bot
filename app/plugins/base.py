from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Awaitable, Callable

LogCallback = Callable[[str, str], Awaitable[None]]


@dataclass(frozen=True)
class PluginFinding:
    title: str
    severity: str
    fingerprint: str
    evidence: str
    endpoint_url: str


class BaseScannerPlugin(ABC):
    """Extension point for bounded, scope-checked audit plugins."""

    key: str
    description: str

    @abstractmethod
    async def scan(self, *, base_url: str, options: dict, log: LogCallback) -> list[PluginFinding]:
        """Run checks only against the supplied, authorized target."""
        raise NotImplementedError
