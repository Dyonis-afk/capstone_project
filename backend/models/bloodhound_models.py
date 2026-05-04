"""
This file contains the request models for analyzing the BloodHound JSON files
and filtering the security findings found in the BloodHound JSON files.
"""

from pydantic import BaseModel, Field
from typing import Optional


class BloodHoundAnalyzeRequest(BaseModel):
    """Request model for analyzing BloodHound JSON content"""
    
    # the raw json content from the BloodHound json file as a string
    json_content: str = Field(
        ...,
        description="BloodHound JSON content as string"
    )
    
    # optional filter incase the user just wants information about a specific edge type.
    filter_edge_type: Optional[str] = Field(
        None,
        description="Optional: Filter results by specific edge type (e.g., 'AdminTo')"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "json_content": "{\"data\": [...]}",
                "filter_edge_type": "AdminTo"
            }
        }


""" 

Filter finding which have already been stored in memory, using 3 optional filters, the edge type,
the target ( e.g Administrator, DCO1 ) and the risk_level ( some edges are more risky than others, for example AdminTo is high risk, while MemberOf is low risk ) 
A list of all the dangerous bloodhound edges can be found in their documentation and other articles written by spectreops:
 - https://bloodhound.specterops.io/get-started/introduction
 - https://specterops.io/blog/2024/09/11/adcs-attack-paths-in-bloodhound-part-3/#:~:text=There%20are%20many%20combinations%20of,Owns
 - https://specterops.io/blog/2018/08/07/bloodhound-2-0/#:~:text=A%20very%20complicated%20attack%20that,during%20the%20ObjectProps%20collection%20method.
 - https://specterops.io/blog/2021/05/25/the-attack-path-management-manifesto/#0ac3

"""

class FindingQueryRequest(BaseModel):
    """Request model for querying specific findings"""
    
    edge_type: Optional[str] = Field(
        None,
        description="Filter by edge type (e.g., 'AdminTo')"
    )
    
    target: Optional[str] = Field(
        None,
        description="Filter by target name (e.g., 'Administrator')"
    )
    
    risk_level: Optional[str] = Field(
        None,
        description="Filter by risk level: High, Medium, or Low (e.g., 'High')"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "edge_type": "AdminTo",
                "risk_level": "High"
            }
        }