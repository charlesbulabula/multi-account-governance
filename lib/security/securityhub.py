from pydantic import BaseModel, Field
from datetime import datetime
from uuid import UUID, uuid4


class BaseRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"from_attributes": True}

# rev 20260518110205-622636fe
