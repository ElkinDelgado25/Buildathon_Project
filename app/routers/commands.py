"""Fixed command API used by terminal-themed clients."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.command import CommandRequest, CommandResponse
from app.services.command_service import CommandDispatcher, CommandValidationError

router = APIRouter(prefix="/commands", tags=["Web CLI Commands"])
dispatcher = CommandDispatcher()


@router.post("", response_model=CommandResponse)
async def execute_command(
    request: CommandRequest, db: AsyncSession = Depends(get_db)
):
    """
    Execute one cataloged command.

    This endpoint never runs arbitrary shell commands, paths, or Docker actions.
    """
    try:
        return await dispatcher.dispatch(request, db)
    except CommandValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
