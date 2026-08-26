from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from detector.traffic_detector import get_latest_result, start_detector


app = FastAPI(
    title="SentinelFlow API",
    description="Real-time network traffic anomaly detection API",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.on_event("startup")
def start_background_detector():
    start_detector()


@app.get("/")
def root():
    return {
        "application": "SentinelFlow",
        "version": "2.0.0",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.get("/api/detection")
def detection():
    return get_latest_result()