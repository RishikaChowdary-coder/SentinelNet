import numpy as np

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest
)

from traffic_generator import generate_dataset


# =========================================================
# FEATURE EXTRACTION
# =========================================================

FEATURES = [
    "packet_count",
    "byte_count",
    "flow_duration",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "destination_port"
]


def extract_features(flow):

    return [
        flow["packet_count"],
        flow["byte_count"],
        flow["flow_duration"],
        flow["packet_rate"],
        flow["byte_rate"],
        flow["average_packet_size"],
        flow["destination_port"]
    ]


# =========================================================
# TRAIN RANDOM FOREST
# =========================================================

def train_random_forest():

    dataset = generate_dataset(
        1000
    )

    X = np.array([
        extract_features(flow)
        for flow in dataset
    ])

    labels = np.array([
        0 if flow["flow_type"] == "normal"
        else 1
        for flow in dataset
    ])

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(
        X,
        labels
    )

    return model


# =========================================================
# TRAIN ISOLATION FOREST
# =========================================================

def train_isolation_forest():

    dataset = [
        flow
        for flow in generate_dataset(1000)
        if flow["flow_type"] == "normal"
    ]

    X = np.array([
        extract_features(flow)
        for flow in dataset
    ])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(X)

    return model


# =========================================================
# TRAIN MODELS
# =========================================================

random_forest = train_random_forest()

isolation_forest = train_isolation_forest()


# =========================================================
# DETECT FLOW
# =========================================================

def detect_flow(flow):

    features = np.array([
        extract_features(flow)
    ])

    # ---------------------------------------------
    # Random Forest prediction
    # ---------------------------------------------

    rf_probability = random_forest.predict_proba(
        features
    )[0][1]


    # ---------------------------------------------
    # Isolation Forest prediction
    # ---------------------------------------------

    isolation_result = isolation_forest.predict(
        features
    )[0]

    isolation_score = isolation_forest.decision_function(
        features
    )[0]


    # Convert anomaly result into 0-1 score

    if isolation_result == -1:

        anomaly_score = 1.0

    else:

        anomaly_score = max(
            0,
            min(
                1,
                0.5 - isolation_score
            )
        )


    # ---------------------------------------------
    # Rule-based score
    # ---------------------------------------------

    rule_score = 0


    if flow["packet_rate"] > 500:

        rule_score += 0.4


    if flow["byte_rate"] > 100000:

        rule_score += 0.2


    if flow["destination_port"] == 53:

        if flow["packet_count"] > 80:

            rule_score += 0.2


    if flow["flow_duration"] < 1:

        rule_score += 0.2


    rule_score = min(
        rule_score,
        1.0
    )


    # ---------------------------------------------
    # Risk fusion
    # ---------------------------------------------

    risk_score = (

        rf_probability * 0.50 +

        anomaly_score * 0.30 +

        rule_score * 0.20

    )


    risk_score = round(
        risk_score * 100
    )


    # ---------------------------------------------
    # Risk level
    # ---------------------------------------------

    if risk_score >= 90:

        level = "CRITICAL"

    elif risk_score >= 70:

        level = "HIGH"

    elif risk_score >= 40:

        level = "MEDIUM"

    else:

        level = "LOW"


    return {

        "risk_score":
            risk_score,

        "level":
            level,

        "random_forest_score":
            round(
                rf_probability * 100,
                2
            ),

        "isolation_score":
            round(
                anomaly_score * 100,
                2
            ),

        "rule_score":
            round(
                rule_score * 100,
                2
            )

    }


# =========================================================
# TEST DETECTOR
# =========================================================

if __name__ == "__main__":

    print("\nSentinelNet ML Detector")
    print("=======================\n")


    test_types = [

        "normal",
        "syn",
        "c2",
        "dga",
        "anomaly"

    ]


    for flow_type in test_types:

        flow = generate_dataset(
            1
        )[0]

        result = detect_flow(
            flow
        )

        print(
            "Flow:",
            flow["flow_type"]
        )

        print(
            "Risk:",
            result["risk_score"]
        )

        print(
            "Level:",
            result["level"]
        )

        print(
            "Random Forest:",
            result["random_forest_score"]
        )

        print(
            "Isolation Forest:",
            result["isolation_score"]
        )

        print(
            "Rule Score:",
            result["rule_score"]
        )

        print(
            "-" * 40
        )