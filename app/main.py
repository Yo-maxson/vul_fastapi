from fastapi import FastAPI
from .entities.pyd_models import Vulners
from .entities.get_parse import get_cve_info_one

app = FastAPI()


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
    if "CVE-" in cve_name:
        vulners = Vulners(**get_cve_info_one(cve_name))
        return {"message": "Результат поиска: ", "Cve": vulners}

    return {"message": "Ошибка в именя CVE", "Cve": cve_name}

#
@app.post("/create_vuln/{cve_name}")
async def create_vuln(cve_name: str):
    vulners = Vulners(**get_cve_info_one(cve_name))
    return {"message": "Товар создан", "product": vulners}
