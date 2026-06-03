from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.memory.database import init_db
from src.api.routes import require_api_key, router
from src.api.forensics import router as forensics_router
from src.config import CORS_ORIGINS

app = FastAPI(title="SentinelForge", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(forensics_router, dependencies=[Depends(require_api_key)])


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "service": "sentinelforge"}
