from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import random
import time

from traffic_generator import generate_flow
from detector import detect_flow

from forensic_logger import (
    create_forensic_record,
    get_forensic_records,
    get_latest_forensic_record,
    verify_hash_chain
)


app = FastAPI(
    title="SentinelNet API",
    description="AI-Based Passive Detection of Cyber Threats",
    version="1.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


current_scenario = "baseline"

scenario_to_flow = {
    "baseline": "normal",
    "syn": "syn",
    "c2": "c2",
    "dga": "dga",
    "anomaly": "anomaly"
}

last_logged_event = None
latest_forensic_record = None


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "SentinelNet Backend is Running",
        "status": "online"
    }


# --------------------------------------------------
# DASHBOARD STATUS
# --------------------------------------------------

@app.get("/api/status")
def get_status():

    global current_scenario
    global last_logged_event
    global latest_forensic_record

    flow_type = scenario_to_flow.get(
        current_scenario,
        "normal"
    )

    flow = generate_flow(flow_type)

    detection = detect_flow(flow)

    # -------------------------------
    # Dashboard traffic statistics
    # -------------------------------

    if current_scenario == "baseline":

        packets = random.randint(27000, 30000)
        flows = random.randint(350, 430)
        sources = random.randint(110, 140)
        active_threats = 0

    elif current_scenario == "syn":

        packets = random.randint(80000, 95000)
        flows = random.randint(700, 900)
        sources = random.randint(180, 240)
        active_threats = 1

    elif current_scenario == "c2":

        packets = random.randint(35000, 42000)
        flows = random.randint(430, 520)
        sources = random.randint(120, 160)
        active_threats = 1

    elif current_scenario == "dga":

        packets = random.randint(48000, 56000)
        flows = random.randint(500, 600)
        sources = random.randint(130, 180)
        active_threats = 1

    elif current_scenario == "anomaly":

        packets = random.randint(40000, 47000)
        flows = random.randint(450, 550)
        sources = random.randint(140, 190)
        active_threats = 1

    else:

        packets = random.randint(27000, 30000)
        flows = random.randint(350, 430)
        sources = random.randint(110, 140)
        active_threats = 0


    # -------------------------------
    # Risk
    # -------------------------------

    risk_score = detection["risk_score"]

    if current_scenario == "baseline":
        risk_score = min(risk_score, 30)


    rf_score = detection["random_forest_score"]
    isolation_score = detection["isolation_score"]
    rule_score = detection["rule_score"]


    # -------------------------------
    # Confidence
    # -------------------------------

    if current_scenario == "baseline":

        confidence = round(
            100
            - (
                isolation_score * 0.5
                + rule_score * 0.3
                + rf_score * 0.2
            )
        )

    else:

        confidence = round(
            rf_score * 0.5
            + isolation_score * 0.3
            + rule_score * 0.2
        )


    confidence = max(
        50,
        min(confidence, 99)
    )


    # -------------------------------
    # Forensic logging
    # -------------------------------

    forensic_record = None


    if risk_score >= 70:

        if last_logged_event != current_scenario:

            forensic_record = create_forensic_record(
                flow,
                detection,
                current_scenario
            )

            last_logged_event = current_scenario

            latest_forensic_record = forensic_record

    else:

        if current_scenario == "baseline":

            last_logged_event = None
            latest_forensic_record = None


    # -------------------------------
    # Response
    # -------------------------------

    return {

        "status": "online",

        "scenario": current_scenario,

        "packets_per_second": packets,

        "active_flows": flows,

        "active_sources": sources,

        "active_threats": active_threats,

        "risk_score": risk_score,

        "confidence": confidence,

        "ml_details": {

            "random_forest":
                detection["random_forest_score"],

            "isolation_forest":
                detection["isolation_score"],

            "rule_score":
                detection["rule_score"]
        },

        "flow_features": {

            "protocol":
                flow["protocol"],

            "source_port":
                flow["source_port"],

            "destination_port":
                flow["destination_port"],

            "packet_count":
                flow["packet_count"],

            "byte_count":
                flow["byte_count"],

            "flow_duration":
                flow["flow_duration"],

            "packet_rate":
                flow["packet_rate"],

            "byte_rate":
                flow["byte_rate"],

            "average_packet_size":
                flow["average_packet_size"]
        },

        "forensic_record":
            forensic_record,

        "latest_forensic_record":
            latest_forensic_record,

        "forensic_event_logged":
            forensic_record is not None,

        "timestamp":
            time.time()
    }


# --------------------------------------------------
# CHANGE SCENARIO
# --------------------------------------------------

@app.post("/api/scenario/{scenario}")
def set_scenario(scenario: str):

    global current_scenario
    global last_logged_event
    global latest_forensic_record

    allowed_scenarios = [
        "baseline",
        "syn",
        "c2",
        "dga",
        "anomaly"
    ]


    if scenario not in allowed_scenarios:

        return {

            "status": "error",

            "message":
                "Unknown scenario",

            "allowed_scenarios":
                allowed_scenarios
        }


    current_scenario = scenario


    if scenario == "baseline":

        last_logged_event = None
        latest_forensic_record = None


    return {

        "status": "success",

        "scenario":
            current_scenario,

        "message":
            f"Scenario changed to {scenario}"
    }


# --------------------------------------------------
# FORENSIC HISTORY
# --------------------------------------------------

@app.get("/api/forensics")
def get_forensics():

    records = get_forensic_records()

    return {

        "status": "success",

        "count": len(records),

        "records": records
    }


# --------------------------------------------------
# LATEST FORENSIC RECORD
# --------------------------------------------------

@app.get("/api/forensics/latest")
def get_latest_forensics():

    return {

        "status": "success",

        "record":
            get_latest_forensic_record()
    }


# --------------------------------------------------
# VERIFY HASH CHAIN
# --------------------------------------------------

@app.get("/api/forensics/verify")
def verify_forensics():

    result = verify_hash_chain()

    return {

        "status": "success",

        **result
    }