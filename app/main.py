from fastapi import FastAPI, HTTPException

from entities.pyd_models import Vulners
from entities.get_parse import get_cve_info_one
from fastapi.responses import JSONResponse
from fastapi.requests import Request
from fastapi.exceptions import RequestValidationError

app = FastAPI()

@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": f"Упс! Ошибка: {exc.detail}"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"errors": exc.errors(), "message": "Ошибка валидации данных"}
    )

@app.get("/")
async def root():
    return {"message": "Hello World"}


@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hello {name}"}

@app.get("/vulners")
def get_vulners():
    return {"Vulners": ["CVE-2025-0435", "CVE-2025-0442", "CVE-2025-0438"]}

@app.get("/info_cve")
async def get_cve_org(cve_name: str):
    if "CVE-" not in cve_name:
        raise HTTPException(status_code=400, detail=f"Ошибка в именя CVE - {cve_name}")
    vulners = Vulners(**get_cve_info_one(cve_name))
    return {"message": "Результат поиска: ", "Cve": vulners}

@app.post("/create_vuln/{cve_name}")
async def create_vuln(cve_name: str):
    if "CVE-" not in cve_name:
        raise HTTPException(status_code=400, detail=f"Ошибка в именя CVE - {cve_name}")
    vulners = Vulners(**get_cve_info_one(cve_name))
    print(vulners)
    print(vulners.name)
    return JSONResponse(
        status_code=201,
        content={"message": f"Cve #{vulners.name} успешно создана "},
        headers={"X-Custom-Header": "Create_vuln"}
    )

def foo():
    print('bar')