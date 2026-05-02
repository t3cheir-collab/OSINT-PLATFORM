from sqlalchemy import Column, Integer, String, JSON, DateTime
from app.database import Base
import datetime

class IOCResult(Base):
    __tablename__ = "ioc_results"

    id = Column(Integer, primary_key=True, index=True)
    ioc = Column(String, index=True)
    type = Column(String)
    score = Column(Integer)
    verdict = Column(String)
    results = Column(JSON)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)