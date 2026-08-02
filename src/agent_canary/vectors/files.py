"""File canary vector — plant honeypot files and watch for access.

Uses the watchdog library for filesystem event monitoring. Falls back to
stat-based polling on platforms where inotify/ReadDirectoryChanges does
not surface open-for-read events.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from ..models import Canary, ScopeRule, TriggerEvent, Vector
from ..registry import Registry
from ..scope_notice import (
    NoticeMode,
    parse_notice_mode,
    prefix_file_content,
    render_notice,
)
from ..templates import get_template

logger = logging.getLogger("agent_canary.vectors.files")

# Type alias for the alert callback
AlertCallback = Callable[[TriggerEvent], None]


# ---------------------------------------------------------------------------
# Planting
# ---------------------------------------------------------------------------

def plant_file(
    registry: Registry,
    path: str | Path,
    template_name: str,
    scope: ScopeRule | None = None,
    notice_mode: str | NoticeMode = "off",
) -> Canary:
    """Generate honeypot content from a template, write it to *path*, and
    register the canary in the registry.

    notice_mode: off | static | stochastic
      When not off, a scope-notice banner is prepended at plant time
      (access_n=1). Soft boundary speech for agents; not a hard control.

    Returns the newly created Canary object.
    """
    path = Path(path)
    canary_id = Canary.generate_id(Vector.FILE, str(path))
    mode = parse_notice_mode(notice_mode)

    content = get_template(template_name)(canary_id)
    notice = render_notice(canary_id, mode, access_n=1)
    if notice is not None:
        content = prefix_file_content(content, notice)

    # Ensure parent directories exist
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    canary = Canary(
        id=canary_id,
        vector=Vector.FILE,
        name=path.name,
        path_or_url=str(path),
        scope=scope or ScopeRule(),
        template=template_name,
        notice_mode=mode.value,
    )
    registry.add_canary(canary)
    logger.info(
        "Planted file canary %s at %s (template=%s notice=%s)",
        canary_id,
        path,
        template_name,
        mode.value,
    )
    return canary


# ---------------------------------------------------------------------------
# Filesystem watcher
# ---------------------------------------------------------------------------

class _CanaryEventHandler(FileSystemEventHandler):
    """Watchdog handler that fires when a canary file is touched."""

    def __init__(
        self,
        registry: Registry,
        watched_paths: dict[str, Canary],
        callback: AlertCallback | None,
    ):
        super().__init__()
        self.registry = registry
        self.watched_paths = watched_paths
        self.callback = callback
        # Track last trigger time per path to debounce rapid duplicate events
        self._last_trigger: dict[str, float] = {}
        self._debounce_secs = 2.0

    def _handle(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        src = os.path.normpath(event.src_path)
        canary = self.watched_paths.get(src)
        if canary is None or not canary.active:
            return

        now = time.time()
        last = self._last_trigger.get(src, 0.0)
        if now - last < self._debounce_secs:
            return
        self._last_trigger[src] = now

        access_n = self.registry.bump_access_count(canary.id) or (
            canary.access_count + 1
        )
        notice = render_notice(canary.id, canary.notice_mode, access_n=access_n)
        trigger = TriggerEvent(
            canary_id=canary.id,
            vector=Vector.FILE,
            raw_request={"file_path": src, "event_type": event.event_type},
            scope_notice=notice.to_dict() if notice else None,
        )
        self.registry.log_trigger(trigger)
        logger.warning(
            "Canary triggered: %s (%s) via %s notice=%s",
            canary.id,
            src,
            event.event_type,
            notice.family if notice else "off",
        )

        if self.callback:
            try:
                self.callback(trigger)
            except Exception:
                logger.exception("Alert callback failed for canary %s", canary.id)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._handle(event)

    # watchdog on some platforms fires on_opened for read access
    def on_opened(self, event: FileSystemEvent) -> None:  # type: ignore[override]
        self._handle(event)

    # Fallback: some backends surface reads as on_accessed
    def on_accessed(self, event: FileSystemEvent) -> None:  # type: ignore[override]
        self._handle(event)


class FileWatcher:
    """Monitor all registered file canaries for access events.

    Uses watchdog's native observer where available, with an option to
    fall back to polling for platforms that lack inotify/kqueue/
    ReadDirectoryChanges support for read events.
    """

    def __init__(
        self,
        registry: Registry,
        callback: AlertCallback | None = None,
        use_polling: bool = False,
        poll_interval: float = 1.0,
    ):
        self.registry = registry
        self.callback = callback
        self.use_polling = use_polling
        self.poll_interval = poll_interval

        self._observer: Observer | PollingObserver | None = None
        self._watched_paths: dict[str, Canary] = {}
        self._lock = threading.Lock()

    def _build_watch_map(self) -> dict[str, Canary]:
        """Build a normalized-path -> Canary map from the registry."""
        result: dict[str, Canary] = {}
        for canary in self.registry.list_canaries():
            if canary.vector == Vector.FILE and canary.active:
                norm = os.path.normpath(canary.path_or_url)
                result[norm] = canary
        return result

    def start(self) -> None:
        """Start watching all registered file canaries."""
        with self._lock:
            if self._observer is not None:
                return  # already running

            self._watched_paths = self._build_watch_map()
            if not self._watched_paths:
                logger.info("No active file canaries to watch")
                return

            handler = _CanaryEventHandler(self.registry, self._watched_paths, self.callback)

            if self.use_polling:
                self._observer = PollingObserver(timeout=self.poll_interval)
            else:
                self._observer = Observer()

            # Deduplicate parent directories so we don't double-watch
            dirs_to_watch: set[str] = set()
            for p in self._watched_paths:
                dirs_to_watch.add(os.path.dirname(p))

            for d in dirs_to_watch:
                self._observer.schedule(handler, d, recursive=False)

            self._observer.daemon = True
            self._observer.start()
            logger.info(
                "FileWatcher started, monitoring %d canary files across %d directories",
                len(self._watched_paths),
                len(dirs_to_watch),
            )

    def stop(self) -> None:
        """Stop the filesystem watcher."""
        with self._lock:
            if self._observer is not None:
                self._observer.stop()
                self._observer.join(timeout=5)
                self._observer = None
                logger.info("FileWatcher stopped")

    def refresh(self) -> None:
        """Rebuild the watch list from the registry (e.g., after planting new files)."""
        self.stop()
        self.start()

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._observer is not None and self._observer.is_alive()


# ---------------------------------------------------------------------------
# Manual access check (for MCP tool wrappers)
# ---------------------------------------------------------------------------

def check_file_access(registry: Registry, path: str | Path) -> TriggerEvent | None:
    """Manually check whether a file path corresponds to a registered canary.

    Call this from MCP tool wrappers (e.g., read_file, cat) to detect agent
    access that bypasses filesystem events. Returns a TriggerEvent if the
    path matches an active canary, otherwise None.
    """
    norm = os.path.normpath(str(path))
    canary = None
    for c in registry.list_canaries():
        if c.vector == Vector.FILE and c.active and os.path.normpath(c.path_or_url) == norm:
            canary = c
            break

    if canary is None:
        return None

    access_n = registry.bump_access_count(canary.id) or (canary.access_count + 1)
    notice = render_notice(canary.id, canary.notice_mode, access_n=access_n)
    trigger = TriggerEvent(
        canary_id=canary.id,
        vector=Vector.FILE,
        raw_request={"file_path": norm, "check_type": "manual"},
        scope_notice=notice.to_dict() if notice else None,
    )
    registry.log_trigger(trigger)
    logger.warning(
        "Manual check triggered canary %s at %s notice=%s",
        canary.id,
        norm,
        notice.family if notice else "off",
    )
    return trigger
