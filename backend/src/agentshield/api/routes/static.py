"""Static asset and single-page application router."""

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse

from agentshield.core.config import get_settings

router = APIRouter()


@router.get(
    "/{full_path:path}",
    include_in_schema=False,
    response_class=Response,
)
async def serve_spa(request: Request, full_path: str) -> Response:
    """Serve single-page application static bundle or fallback HTML."""
    # Never intercept /api or /health
    if full_path.startswith("api/") or full_path == "api" or full_path.startswith("health"):
        raise HTTPException(status_code=404, detail="Not Found")

    settings = get_settings()
    dist_dir = settings.effective_frontend_dist_dir

    # 1. Try exact file in dist
    if full_path:
        # Prevent directory traversal
        target_file = (dist_dir / full_path).resolve()
        if target_file.is_relative_to(dist_dir.resolve()) and target_file.is_file():
            return FileResponse(target_file)

    # 2. Try index.html in dist
    index_file = dist_dir / "index.html"
    if index_file.is_file():
        return FileResponse(index_file)

    # 3. Fallback when frontend has not been compiled yet
    fallback_html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AgentShield</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #0f172a; color: #f8fafc; display: flex; align-items: center;
           justify-content: center; height: 100vh; margin: 0; }
    .card { background: #1e293b; padding: 2rem; border-radius: 0.5rem; max-width: 500px;
            border: 1px solid #334155; text-align: center; }
    h1 { margin-top: 0; color: #38bdf8; }
    code { background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 0.25rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ AgentShield</h1>
    <p>Management server is running on loopback.</p>
    <p>To serve the dashboard UI, build the frontend bundle:</p>
    <p><code>cd frontend &amp;&amp; pnpm build</code></p>
    <p><a href="/api/v1/status" style="color: #38bdf8;">View System Status API</a></p>
  </div>
</body>
</html>
"""
    return HTMLResponse(content=fallback_html, status_code=200)
