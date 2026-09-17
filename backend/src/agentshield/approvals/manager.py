"""In-memory thread-safe and asyncio-aware approval manager."""

import asyncio
import contextlib
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from agentshield.approvals.models import ApprovalRequest, ApprovalStatus, FindingSummary
from agentshield.core.errors import ConflictError, NotFoundError
from agentshield.core.logging import get_logger

logger = get_logger("agentshield.approvals.manager")


async def _check_disconnect(
    future: asyncio.Future[ApprovalStatus],
    is_disconnected: Callable[[], Awaitable[bool]],
) -> bool:
    while not future.done():
        with contextlib.suppress(Exception):
            if await is_disconnected():
                return True
        await asyncio.sleep(0.25)
    return False


class ApprovalManager:
    """Coordinates manual approval holds, timeouts, disconnects, and UI events."""

    def __init__(self, max_history: int = 500) -> None:
        self.max_history = max_history
        self._lock = asyncio.Lock()
        self._requests: OrderedDict[str, ApprovalRequest] = OrderedDict()
        self._futures: dict[str, asyncio.Future[ApprovalStatus]] = {}
        self._subscribers: set[asyncio.Queue[tuple[str, dict[str, Any]]]] = set()
        self._background_tasks: set[asyncio.Task[Any]] = set()

    def _track_task(self, task: asyncio.Task[Any]) -> None:
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def create_request(
        self,
        *,
        request_fingerprint: str,
        policy_version: str,
        provider: str,
        model: str | None,
        endpoint: str,
        direction: str = "REQUEST",
        agent: str | None = None,
        project: str | None = None,
        session_id: str | None = None,
        findings: tuple[FindingSummary, ...] = (),
        timeout_seconds: float = 60.0,
        raw_payload_masked: dict[str, Any] | None = None,
        redacted_payload: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        """Create and register a new in-flight approval hold."""
        request_id = uuid4().hex
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=max(1.0, timeout_seconds))

        req = ApprovalRequest(
            id=request_id,
            request_fingerprint=request_fingerprint,
            policy_version=policy_version,
            provider=provider,
            model=model,
            endpoint=endpoint,
            direction=direction,
            agent=agent,
            project=project,
            session_id=session_id,
            findings=findings,
            created_at=now,
            expires_at=expires_at,
            status=ApprovalStatus.PENDING,
            raw_payload_masked=raw_payload_masked,
            redacted_payload=redacted_payload,
        )

        future: asyncio.Future[ApprovalStatus] | None = None
        try:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
        except RuntimeError:
            future = None

        self._requests[request_id] = req
        if future is not None:
            self._futures[request_id] = future

        # Prune oldest history if exceeding capacity
        while len(self._requests) > self.max_history:
            oldest_id, oldest_req = next(iter(self._requests.items()))
            if oldest_req.status.is_terminal:
                self._requests.pop(oldest_id)
                self._futures.pop(oldest_id, None)
            else:
                break

        logger.info(
            "Approval hold created: id=%s provider=%s endpoint=%s findings=%d timeout=%.1fs",
            request_id,
            provider,
            endpoint,
            len(findings),
            timeout_seconds,
        )

        self.publish_event(
            "approval_pending",
            {
                "id": req.id,
                "request_fingerprint": req.request_fingerprint,
                "provider": req.provider,
                "model": req.model,
                "endpoint": req.endpoint,
                "finding_count": len(req.findings),
                "finding_categories": [f.category for f in req.findings],
                "created_at": req.created_at.isoformat(),
                "expires_at": req.expires_at.isoformat(),
                "remaining_seconds": req.remaining_seconds,
                "agent": req.agent,
                "project": req.project,
            },
        )

        return req

    async def _resolve_wait_outcome(
        self,
        request_id: str,
        future: asyncio.Future[ApprovalStatus],
        disconnect_task: asyncio.Task[bool] | None,
        done: set[asyncio.Task[Any] | asyncio.Future[Any]],
    ) -> ApprovalStatus:
        if disconnect_task is not None and disconnect_task in done and disconnect_task.result():
            await self.cancel(request_id, reason="Client disconnected")
            return ApprovalStatus.CANCELLED

        if future in done:
            return future.result()

        await self.expire(request_id, reason="Approval timed out")
        return ApprovalStatus.EXPIRED

    async def wait_for_decision(
        self,
        request_id: str,
        timeout_seconds: float,
        is_client_disconnected: Callable[[], Awaitable[bool]] | None = None,
    ) -> ApprovalStatus:
        """Wait for an operator decision, client disconnect, or expiration."""
        req = self._requests.get(request_id)
        if req is None:
            raise NotFoundError(f"No pending approval hold for request '{request_id}'")

        if req.status.is_terminal:
            return req.status

        future = self._futures.get(request_id)
        if future is None:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            self._futures[request_id] = future

        if future.done():
            return future.result()

        disconnect_task: asyncio.Task[bool] | None = None
        if is_client_disconnected is not None:
            disconnect_task = asyncio.create_task(_check_disconnect(future, is_client_disconnected))

        try:
            wait_tasks: list[asyncio.Task[Any] | asyncio.Future[Any]] = [future]
            if disconnect_task is not None:
                wait_tasks.append(disconnect_task)

            done, _ = await asyncio.wait(
                wait_tasks,
                timeout=max(0.1, timeout_seconds),
                return_when=asyncio.FIRST_COMPLETED,
            )
            return await self._resolve_wait_outcome(request_id, future, disconnect_task, done)
        finally:
            if disconnect_task is not None and not disconnect_task.done():
                disconnect_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await disconnect_task

    async def approve(self, request_id: str, reason: str | None = None) -> ApprovalRequest:
        """Approve a pending request atomically."""
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                raise NotFoundError(f"Approval request '{request_id}' not found")
            if req.status is not ApprovalStatus.PENDING:
                raise ConflictError(
                    f"Approval request '{request_id}' is already {req.status.value}"
                )

            now = datetime.now(UTC)
            req.status = ApprovalStatus.APPROVED
            req.decided_at = now
            req.decision_reason = reason

            fut = self._futures.get(request_id)
            if fut is not None and not fut.done():
                fut.set_result(ApprovalStatus.APPROVED)

            logger.info("Approval granted: id=%s reason=%s", request_id, reason or "None")

            self.publish_event(
                "approval_resolved",
                {
                    "id": req.id,
                    "status": req.status.value,
                    "decided_at": now.isoformat(),
                    "reason": reason,
                },
            )
            return req

    async def deny(self, request_id: str, reason: str | None = None) -> ApprovalRequest:
        """Deny a pending request atomically."""
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                raise NotFoundError(f"Approval request '{request_id}' not found")
            if req.status is not ApprovalStatus.PENDING:
                raise ConflictError(
                    f"Approval request '{request_id}' is already {req.status.value}"
                )

            now = datetime.now(UTC)
            req.status = ApprovalStatus.DENIED
            req.decided_at = now
            req.decision_reason = reason
            req.clear_payloads()

            fut = self._futures.get(request_id)
            if fut is not None and not fut.done():
                fut.set_result(ApprovalStatus.DENIED)

            logger.info("Approval denied: id=%s reason=%s", request_id, reason or "None")

            self.publish_event(
                "approval_resolved",
                {
                    "id": req.id,
                    "status": req.status.value,
                    "decided_at": now.isoformat(),
                    "reason": reason,
                },
            )
            return req

    async def cancel(self, request_id: str, reason: str | None = None) -> ApprovalRequest | None:
        """Cancel an in-flight hold (e.g. client disconnect)."""
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return None
            if req.status is not ApprovalStatus.PENDING:
                return req

            now = datetime.now(UTC)
            req.status = ApprovalStatus.CANCELLED
            req.decided_at = now
            req.decision_reason = reason or "Cancelled"
            req.clear_payloads()

            fut = self._futures.get(request_id)
            if fut is not None and not fut.done():
                fut.set_result(ApprovalStatus.CANCELLED)

            logger.info("Approval cancelled: id=%s reason=%s", request_id, req.decision_reason)

            self.publish_event(
                "approval_resolved",
                {
                    "id": req.id,
                    "status": req.status.value,
                    "decided_at": now.isoformat(),
                    "reason": req.decision_reason,
                },
            )
            return req

    async def expire(self, request_id: str, reason: str | None = None) -> ApprovalRequest | None:
        """Expire a pending hold after timeout."""
        async with self._lock:
            req = self._requests.get(request_id)
            if req is None:
                return None
            if req.status is not ApprovalStatus.PENDING:
                return req

            now = datetime.now(UTC)
            req.status = ApprovalStatus.EXPIRED
            req.decided_at = now
            req.decision_reason = reason or "Approval timed out"
            req.clear_payloads()

            fut = self._futures.get(request_id)
            if fut is not None and not fut.done():
                fut.set_result(ApprovalStatus.EXPIRED)

            logger.info("Approval expired: id=%s", request_id)

            self.publish_event(
                "approval_resolved",
                {
                    "id": req.id,
                    "status": req.status.value,
                    "decided_at": now.isoformat(),
                    "reason": req.decision_reason,
                },
            )
            return req

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        """Get an approval request by ID."""
        req = self._requests.get(request_id)
        if req and req.status is ApprovalStatus.PENDING and req.remaining_seconds <= 0.0:
            self._track_task(asyncio.create_task(self.expire(request_id)))
        return req

    def list_requests(self, status: ApprovalStatus | None = None) -> list[ApprovalRequest]:
        """List requests, optionally filtered by status."""
        results: list[ApprovalRequest] = []
        for req in reversed(self._requests.values()):
            if req.status is ApprovalStatus.PENDING and req.remaining_seconds <= 0.0:
                self._track_task(asyncio.create_task(self.expire(req.id)))
            if status is None or req.status is status:
                results.append(req)
        return results

    def subscribe(self) -> asyncio.Queue[tuple[str, dict[str, Any]]]:
        """Subscribe to real-time events."""
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[tuple[str, dict[str, Any]]]) -> None:
        """Unsubscribe from real-time events."""
        self._subscribers.discard(queue)

    def publish_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an event to all active subscribers without blocking."""
        dead_subscribers: list[asyncio.Queue[tuple[str, dict[str, Any]]]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait((event_type, data))
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait((event_type, data))
                except Exception:
                    dead_subscribers.append(queue)
            except Exception:
                dead_subscribers.append(queue)

        for dead in dead_subscribers:
            self._subscribers.discard(dead)
