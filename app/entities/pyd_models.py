from pydantic import BaseModel
from datetime import date


class Cve_name(BaseModel):
    name: str

class Vulners(BaseModel):

    name: str
    baseScore: float = 0.0
    vectorString_v3: str = None
    link: str
    publicated: bool
    datePublished: date = None
    dateUpdated: date = None
