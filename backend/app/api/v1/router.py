from fastapi import APIRouter
from backend.app.api.v1 import (
    health,
    auth,
    cases,
    evidence,
    timeline,
    correlation,
    memory,
    ml,
    deleted,
    timestamps,
    anti_forensics,
    cloud,
    reports,
    evaluation,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(health.router)
api_router.include_router(cases.router)
api_router.include_router(evidence.router)
api_router.include_router(timeline.router)
api_router.include_router(correlation.router)
api_router.include_router(memory.router)
api_router.include_router(ml.router)
api_router.include_router(deleted.router)
api_router.include_router(timestamps.router)
api_router.include_router(anti_forensics.router)
api_router.include_router(cloud.router)
api_router.include_router(reports.router)
api_router.include_router(evaluation.router)






