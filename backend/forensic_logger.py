import hashlib
import json
import time
import os


# =========================================================
# FORENSIC STORAGE
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FORENSIC_FILE = os.path.join(
    BASE_DIR,
    "forensic_records.json"
)


# =========================================================
# LOAD EXISTING RECORDS
# =========================================================

def load_records():
    if not os.path.exists(FORENSIC_FILE):
        return []

    try:
        with open(
            FORENSIC_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

            if isinstance(data, list):
                return data

            return []

    except (json.JSONDecodeError, OSError):
        return []


# =========================================================
# INITIALIZE HASH CHAIN
# =========================================================

records = load_records()

if records:
    previous_hash = records[-1].get(
        "hash",
        "0" * 64
    )
else:
    previous_hash = "0" * 64


# =========================================================
# SAVE RECORDS
# =========================================================

def save_records():

    with open(
        FORENSIC_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            records,
            file,
            indent=4
        )


# =========================================================
# CREATE FORENSIC RECORD
# =========================================================

def create_forensic_record(
    flow,
    detection,
    scenario
):

    global previous_hash

    record = {

        "timestamp": time.time(),

        "scenario": scenario,

        "flow": {

            "protocol": flow["protocol"],

            "source_port": flow["source_port"],

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

        "detection": {

            "risk_score":
                detection["risk_score"],

            "level":
                detection["level"],

            "random_forest_score":
                detection["random_forest_score"],

            "isolation_score":
                detection["isolation_score"],

            "rule_score":
                detection["rule_score"]

        },

        "previous_hash": previous_hash

    }


    # =====================================================
    # CREATE SHA-256 HASH
    # =====================================================

    record_string = json.dumps(
        record,
        sort_keys=True
    )

    current_hash = hashlib.sha256(
        record_string.encode("utf-8")
    ).hexdigest()


    # Add hash to record
    record["hash"] = current_hash


    # Add record to history
    records.append(record)


    # Update previous hash
    previous_hash = current_hash


    # Save to JSON file
    save_records()


    return record


# =========================================================
# GET ALL FORENSIC RECORDS
# =========================================================

def get_forensic_records():
    return records


# =========================================================
# GET LATEST RECORD
# =========================================================

def get_latest_forensic_record():

    if not records:
        return None

    return records[-1]


# =========================================================
# VERIFY HASH CHAIN
# =========================================================

def verify_hash_chain():

    if not records:

        return {
            "valid": True,
            "records": 0,
            "message": "No forensic records found."
        }


    expected_previous_hash = "0" * 64


    for index, record in enumerate(records):

        stored_hash = record.get("hash")


        # Check previous hash
        if record.get("previous_hash") != expected_previous_hash:

            return {
                "valid": False,
                "records": len(records),
                "broken_at": index,
                "message": "Previous hash mismatch."
            }


        # Remove current hash before recalculating
        record_without_hash = {
            key: value
            for key, value in record.items()
            if key != "hash"
        }


        # Recreate original record string
        record_string = json.dumps(
            record_without_hash,
            sort_keys=True
        )


        # Calculate hash again
        calculated_hash = hashlib.sha256(
            record_string.encode("utf-8")
        ).hexdigest()


        # Compare calculated and stored hash
        if calculated_hash != stored_hash:

            return {
                "valid": False,
                "records": len(records),
                "broken_at": index,
                "message": "Record hash mismatch."
            }


        # Move to next record
        expected_previous_hash = stored_hash


    return {
        "valid": True,
        "records": len(records),
        "message": "Forensic hash chain is valid."
    }