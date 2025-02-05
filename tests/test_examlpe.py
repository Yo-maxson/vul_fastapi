from fastapi.testclient import TestClient
from fastapi import FastAPI
from app.main import app

client = TestClient(app)

