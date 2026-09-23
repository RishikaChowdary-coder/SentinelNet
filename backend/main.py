from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import random
import time

app = FastAPI(title="SentinelNet API")

# Allow our frontend to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "SentinelNet Backend is Running",
        "status": "online"
    }


@app.get("/api/status")
def get_status():

    packets = random.randint(27000, 30000)
    flows = random.randint(350, 430)
    sources = random.randint(110, 140)

    return {
        "status": "online",
        "packets_per_second": packets,
        "active_flows": flows,
        "active_sources": sources,
        "risk_score": 18,
        "confidence": 61,
        "active_threats": 0,
        "timestamp": time.time()
    }