# FILE: backend/routers/scenarios.py
# PURPOSE: HTTP endpoints wrapping the AI scenario agent
# SECURITY NOTE: ANTHROPIC_API_KEY/OLLAMA are server-side only; vuln_type is allowlist-validated

import logging
import traceback

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from database import AsyncSessionLocal
from models.scenario import Scenario as ScenarioModel
from ai_engine.scenario_agent import generate_scenario

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])

ALLOWED_VULN_TYPES = {
    "sql_injection", "xss", "csrf", "file_upload", "broken_auth",
    "security_misconfig", "sensitive_data_exposure", "logging_monitoring",
    "supply_chain", "cryptographic_failure", "insecure_design",
    "exceptional_conditions", "underprotected_apis"
}


class ScenarioRequest(BaseModel):
    vuln_type: str
    difficulty: str = "beginner"


@router.post("/generate")
async def create_scenario(req: ScenarioRequest):
    if req.vuln_type not in ALLOWED_VULN_TYPES:
        raise HTTPException(400, f"Unknown vuln_type: {req.vuln_type}")

    logger.info("[SCENARIO] Generating: vuln_type=%s difficulty=%s", req.vuln_type, req.difficulty)
    print(f"[SCENARIO] Generating: vuln_type={req.vuln_type} difficulty={req.difficulty}", flush=True)

    try:
        from ai_engine.providers.factory import get_provider
        provider = get_provider()
        print(f"[AI ENGINE] Using provider: {type(provider).__name__}", flush=True)

        data = await generate_scenario(req.vuln_type, req.difficulty)
        print(f"[SCENARIO] Generation OK: title={data.get('title', '')[:50]}", flush=True)

        async with AsyncSessionLocal() as session:
            db_obj = ScenarioModel(
                vuln_type=req.vuln_type,
                title=data.get("title"),
                steps=data.get("steps"),
                payloads=data.get("payloads"),
                cvss_score=data.get("risk", {}).get("cvss_score"),
            )
            session.add(db_obj)
            await session.commit()
            await session.refresh(db_obj)
        return {"id": db_obj.id, **data}

    except Exception as e:
        tb = traceback.format_exc()
        print(f"[SCENARIO] ERROR: {e}\n{tb}", flush=True)
        logger.error("[SCENARIO] Generation failed: %s", tb)
        raise HTTPException(500, detail=f"{type(e).__name__}: {e}")


@router.get("/")
async def list_scenarios():
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(ScenarioModel).order_by(ScenarioModel.generated_at.desc())
        )
        return result.scalars().all()


@router.get("/{scenario_id}")
async def get_scenario(scenario_id: int):
    async with AsyncSessionLocal() as session:
        obj = await session.get(ScenarioModel, scenario_id)
        if not obj:
            raise HTTPException(404, "Scenario not found")
        return obj
