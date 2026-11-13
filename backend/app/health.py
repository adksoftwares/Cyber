from sqlalchemy import text
from .db import engine
def dependency_status():
    try:
        with engine.connect() as connection: connection.execute(text("SELECT 1"))
        return {"database":"ok"}
    except Exception: return {"database":"unavailable"}
