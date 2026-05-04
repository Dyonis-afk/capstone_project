"""
Basically structures the request from the api so that it is consistent and easy to understand.
"""

from pydantic import BaseModel, Field

class QueryRequest(BaseModel):
    
    question: str = Field(..., description="The question to be processed", example="What is the AdminTo edge in BloodHound?")
    
    class Config:
        schema_extra = {
            "example": {
                "question": "How do I detect DCSync attacks?"
            }
        }