from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc
from sqlmodel import Session, select

from vulnerability_manager.auth import ensure_bootstrap_admin, get_current_user_from_request
from vulnerability_manager.database import create_db_and_tables, engine
from vulnerability_manager.models.organization import Organization
from vulnerability_manager.models.project import Project
from vulnerability_manager.models.service import Service
from vulnerability_manager.models.version import Version
from vulnerability_manager.models.vulnerability import Vulnerability, Severity, VulnStatus
from vulnerability_manager.routers import auth, organizations, projects, services, versions, vulnerabilities, users


@asynccontextmanager
async def lifespan(_app: FastAPI):
    create_db_and_tables()
    with Session(engine) as session:
        ensure_bootstrap_admin(session)
    yield


app = FastAPI(
    title="Security Advisor — Vulnerability Management",
    description="Manage vulnerabilities across Organizations, Projects, Services, and Versions.",
    version="1.0.0",
    lifespan=lifespan,
)

templates = Jinja2Templates(directory="vulnerability_manager/templates")


@app.middleware("http")
async def require_authentication(request: Request, call_next):
    path = request.url.path
    allowlist = {"/login", "/logout", "/api/auth/token"}
    if path in allowlist or path.startswith("/static/"):
        request.state.current_user = None
        request.state.is_authenticated = False
        return await call_next(request)

    with Session(engine) as session:
        try:
            current_user = get_current_user_from_request(request, session)
        except HTTPException:
            if path.startswith("/api/"):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            login_url = f"/login?next={quote(path)}"
            return RedirectResponse(url=login_url, status_code=303)

        request.state.current_user = current_user
        request.state.is_authenticated = True
        response = await call_next(request)
        return response

# Mount routers
app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(projects.router)
app.include_router(services.router)
app.include_router(versions.router)
app.include_router(vulnerabilities.router)
app.include_router(users.router)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request):
    with Session(engine) as session:
        org_count = len(session.exec(select(Organization.id)).all())
        proj_count = len(session.exec(select(Project.id)).all())
        svc_count = len(session.exec(select(Service.id)).all())
        ver_count = len(session.exec(select(Version.id)).all())
        vuln_count = len(session.exec(select(Vulnerability.id)).all())

        severity_counts = {}
        for sev in Severity:
            severity_counts[sev.value] = len(
                session.exec(select(Vulnerability.id).where(Vulnerability.severity == sev)).all()
            )

        status_counts = {}
        for st in VulnStatus:
            status_counts[st.value] = len(
                session.exec(select(Vulnerability.id).where(Vulnerability.status == st)).all()
            )

        recent_vulns = session.exec(
            select(Vulnerability).order_by(desc(Vulnerability.created_at)).limit(10)
        ).all()

    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "org_count": org_count,
            "proj_count": proj_count,
            "svc_count": svc_count,
            "ver_count": ver_count,
            "vuln_count": vuln_count,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "recent_vulns": recent_vulns,
        },
    )
