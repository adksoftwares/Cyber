import time
from collections import defaultdict, deque
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class SecurityMiddleware(BaseHTTPMiddleware):
    """Basic per-process rate limiting and security headers."""
    def __init__(self, app, limit=120, window_seconds=60):
        super().__init__(app)
        self.limit = limit
        self.window = window_seconds
        self.hits = defaultdict(deque)
        self.last_cleanup = time.monotonic()

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = self.hits[ip]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if now - self.last_cleanup > self.window:
            for address in list(self.hits):
                if not self.hits[address]:
                    self.hits.pop(address, None)
            self.last_cleanup = now
        if len(bucket) >= self.limit:
            response = JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)
        else:
            bucket.append(now)
            response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response
