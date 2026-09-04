"""Security middleware enforcing Host validation, Origin/CORS validation, and security headers."""

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agentshield.core.config import Settings, get_settings
from agentshield.core.errors import InvalidHostError, InvalidOriginError


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware adding standard security hardening headers to all HTTP responses."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' http://127.0.0.1:* http://localhost:* ws://127.0.0.1:* ws://localhost:*;"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response


class LoopbackSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing strict loopback Host and Origin validation."""

    def __init__(self, app: object, settings: Settings | None = None) -> None:
        super().__init__(app)  # pyright: ignore[reportArgumentType]
        self.settings = settings or get_settings()

    def _is_valid_host(self, host_header: str | None) -> bool:
        """Verify Host header is strictly a loopback address."""
        if not host_header:
            return False
        # Remove port if present
        host_name = host_header.split(":")[0].strip().lower()
        return host_name in ["127.0.0.1", "localhost", "::1", "[::1]"]

    def _is_valid_origin(self, origin_header: str | None) -> bool:
        """Verify Origin header matches configured loopback origins."""
        if not origin_header:
            return True  # Same-origin or non-browser requests without Origin are permitted
        origin_clean = origin_header.strip().rstrip("/")
        allowed = [o.strip().rstrip("/") for o in self.settings.cors_allowed_origins]
        allowed.extend(
            [
                f"http://127.0.0.1:{self.settings.port}",
                f"http://localhost:{self.settings.port}",
            ]
        )
        return origin_clean in allowed

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # 1. Validate Host header
        host_header = request.headers.get("host")
        if not self._is_valid_host(host_header):
            exc = InvalidHostError(f"Host '{host_header}' is not an authorized loopback interface")
            problem = exc.to_problem_details(instance=str(request.url.path))
            return JSONResponse(
                status_code=400,
                content=problem.model_dump(exclude_none=True),
                headers={"Content-Type": "application/problem+json"},
            )

        origin_header = request.headers.get("origin")

        # 2. Handle CORS Preflight (OPTIONS)
        if request.method == "OPTIONS" and origin_header:
            if not self._is_valid_origin(origin_header):
                exc = InvalidOriginError(f"Origin '{origin_header}' is not allowed")
                problem = exc.to_problem_details(instance=str(request.url.path))
                return JSONResponse(
                    status_code=403,
                    content=problem.model_dump(exclude_none=True),
                    headers={"Content-Type": "application/problem+json"},
                )
            # Valid preflight response
            response = Response(status_code=204)
            response.headers["Access-Control-Allow-Origin"] = origin_header
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = (
                "Authorization, Content-Type, X-Requested-With, X-AgentShield-Token"
            )
            response.headers["Access-Control-Max-Age"] = "600"
            return response

        # 3. Validate Origin on regular requests if present
        if origin_header and not self._is_valid_origin(origin_header):
            exc = InvalidOriginError(f"Origin '{origin_header}' is not allowed")
            problem = exc.to_problem_details(instance=str(request.url.path))
            return JSONResponse(
                status_code=403,
                content=problem.model_dump(exclude_none=True),
                headers={"Content-Type": "application/problem+json"},
            )

        # 4. Process the request
        response = await call_next(request)

        # 5. Attach CORS headers if origin is valid loopback origin (never wildcard)
        if origin_header and self._is_valid_origin(origin_header):
            response.headers["Access-Control-Allow-Origin"] = origin_header
            response.headers["Access-Control-Allow-Credentials"] = "true"

        return response
