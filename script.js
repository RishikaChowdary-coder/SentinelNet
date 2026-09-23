/* =========================================================
   SENTINELNET
   PASSIVE THREAT INTELLIGENCE
   Dashboard logic
========================================================= */


/* =========================================================
   DOM ELEMENTS
========================================================= */

const packetsEl = document.getElementById("packets");
const flowsEl = document.getElementById("flows");
const sourcesEl = document.getElementById("sources");

const riskScoreEl = document.getElementById("riskScore");
const riskCircleEl = document.getElementById("riskCircle");

const riskStatusEl =
    document.getElementById("riskStatus");

const riskLevelEl =
    document.getElementById("riskLevel");

const riskDescriptionTitleEl =
    document.getElementById("riskDescriptionTitle");

const riskDescriptionEl =
    document.getElementById("riskDescription");

const confidenceEl =
    document.getElementById("confidence");

const confidenceBarEl =
    document.getElementById("confidenceBar");

const currentScenarioEl =
    document.getElementById("currentScenario");

const activeThreatsEl =
    document.getElementById("activeThreats");

const alertsListEl =
    document.getElementById("alertsList");

const selectedTypeEl =
    document.getElementById("selectedType");

const investigationTitleEl =
    document.getElementById("investigationTitle");

const investigationRouteEl =
    document.getElementById("investigationRoute");

const investigationConfidenceEl =
    document.getElementById("investigationConfidence");

const evidence1El =
    document.getElementById("evidence1");

const evidence2El =
    document.getElementById("evidence2");

const evidence3El =
    document.getElementById("evidence3");

const sessionIdEl =
    document.getElementById("sessionId");

const observedTimeEl =
    document.getElementById("observedTime");

const toastEl =
    document.getElementById("toast");

const toastMessageEl =
    document.getElementById("toastMessage");

const pauseBtn =
    document.getElementById("pauseBtn");

const injectTopBtn =
    document.getElementById("injectTopBtn");

const restoreBtn =
    document.getElementById("restoreBtn");

const scenarioButtons =
    document.querySelectorAll(".scenario-btn");

const filterButtons =
    document.querySelectorAll(".filter");


/* =========================================================
   APPLICATION STATE
========================================================= */

let currentScenario = "baseline";

let streamRunning = true;

let selectedAlert = null;

let trafficTimer = null;

let chart = null;


/* =========================================================
   BACKEND
========================================================= */

const BACKEND_URL =
    "http://127.0.0.1:8000";


/* =========================================================
   BASELINE DATA
========================================================= */

const baseline = {

    packets: 28420,

    flows: 392,

    sources: 128,

    risk: 18,

    confidence: 61,

    scenario: "Baseline traffic",

    status: "nominal posture",

    level: "LOW",

    title: "Low-level recon activity",

    description:
        "A single source is touching more services than its baseline, but remains below escalation threshold.",

    route:
        "10.42.7.19 → 10.42.0.0/16",

    evidence: [

        "18 unique ports contacted in 5m",

        "73% connection success rate",

        "No payload or persistence signal observed"

    ],

    threat: "RECONNAISSANCE"

};


/* =========================================================
   SCENARIO DATA
========================================================= */

const scenarios = {

    syn: {

        name: "SYN Flood",

        description:
            "Abnormal SYN activity is exceeding the learned traffic baseline.",

        packets: 86700,

        flows: 1480,

        sources: 1284,

        risk: 94,

        confidence: 97,

        level: "CRITICAL",

        status: "critical threat detected",

        title: "Volumetric SYN pressure",

        route: "10.18.4.21 → protected edge",

        evidence: [

            "98.2% of observed packets are SYN",

            "1,284 unique source addresses in 60s",

            "SYN/ACK response ratio below baseline"

        ],

        threat: "SYN FLOOD",

        severity: "critical"

    },


    c2: {

        name: "C2 Beacon",

        description:
            "Periodic callback behavior is inconsistent with the normal communication baseline.",

        packets: 38120,

        flows: 618,

        sources: 94,

        risk: 87,

        confidence: 94,

        level: "HIGH",

        status: "suspicious callback pattern",

        title: "Periodic C2 beacon",

        route: "10.42.7.19 → 172.16.8.44",

        evidence: [

            "Regular 30-second connection intervals",

            "Low-volume recurring outbound sessions",

            "Destination remained consistent across windows"

        ],

        threat: "C2 BEACON",

        severity: "high"

    },


    dga: {

        name: "DGA Tunnel",

        description:
            "DNS requests show unusually high entropy and generated-domain characteristics.",

        packets: 51400,

        flows: 840,

        sources: 74,

        risk: 81,

        confidence: 92,

        level: "HIGH",

        status: "dns anomaly detected",

        title: "Generated-domain DNS pattern",

        route: "10.42.5.77 → DNS resolver",

        evidence: [

            "High-entropy domain labels detected",

            "Elevated NXDOMAIN response ratio",

            "Repeated short DNS queries across intervals"

        ],

        threat: "DGA TUNNEL",

        severity: "high"

    },


    anomaly: {

        name: "Unknown Anomaly",

        description:
            "The observed flow differs significantly from the learned behavioral baseline.",

        packets: 43600,

        flows: 711,

        sources: 211,

        risk: 72,

        confidence: 84,

        level: "ANOMALY",

        status: "novel behavior detected",

        title: "Unknown traffic behavior",

        route: "10.42.12.8 → external network",

        evidence: [

            "Flow behavior differs from learned baseline",

            "Unusual packet-size distribution detected",

            "No known signature matched the event"

        ],

        threat: "UNKNOWN ANOMALY",

        severity: "anomaly"

    }

};


/* =========================================================
   BACKEND SCENARIO INFORMATION
========================================================= */

const backendScenarioMeta = {

    baseline: {

        name: "Baseline traffic",

        level: "LOW",

        status: "nominal posture",

        title: "Low-level recon activity",

        description:
            "A single source is touching more services than its baseline, but remains below escalation threshold.",

        route:
            "10.42.7.19 → 10.42.0.0/16",

        threat:
            "RECONNAISSANCE",

        evidence: [

            "18 unique ports contacted in 5m",

            "73% connection success rate",

            "No payload or persistence signal observed"

        ]

    },


    syn: {

        name: "SYN Flood",

        level: "CRITICAL",

        status: "critical threat detected",

        title: "Volumetric SYN pressure",

        description:
            "Abnormal SYN activity is exceeding the learned traffic baseline.",

        route:
            "10.18.4.21 → protected edge",

        threat:
            "SYN FLOOD",

        evidence: [

            "98.2% of observed packets are SYN",

            "1,284 unique source addresses in 60s",

            "SYN/ACK response ratio below baseline"

        ]

    },


    c2: {

        name: "C2 Beacon",

        level: "HIGH",

        status: "suspicious callback pattern",

        title: "Periodic C2 beacon",

        description:
            "Periodic callback behavior is inconsistent with the normal communication baseline.",

        route:
            "10.42.7.19 → 172.16.8.44",

        threat:
            "C2 BEACON",

        evidence: [

            "Regular 30-second connection intervals",

            "Low-volume recurring outbound sessions",

            "Destination remained consistent across windows"

        ]

    },


    dga: {

        name: "DGA Tunnel",

        level: "HIGH",

        status: "dns anomaly detected",

        title: "Generated-domain DNS pattern",

        description:
            "DNS requests show unusually high entropy and generated-domain characteristics.",

        route:
            "10.42.5.77 → DNS resolver",

        threat:
            "DGA TUNNEL",

        evidence: [

            "High-entropy domain labels detected",

            "Elevated NXDOMAIN response ratio",

            "Repeated short DNS queries across intervals"

        ]

    },


    anomaly: {

        name: "Unknown Anomaly",

        level: "ANOMALY",

        status: "novel behavior detected",

        title: "Unknown traffic behavior",

        description:
            "The observed flow differs significantly from the learned behavioral baseline.",

        route:
            "10.42.12.8 → external network",

        threat:
            "UNKNOWN ANOMALY",

        evidence: [

            "Flow behavior differs from learned baseline",

            "Unusual packet-size distribution detected",

            "No known signature matched the event"

        ]

    }

};


/* =========================================================
   ALERT DATA
========================================================= */

const alerts = [

    {

        id: 1,

        name: "Low-level recon activity",

        type: "RECONNAISSANCE",

        severity: "low",

        source: "10.42.7.19",

        destination: "10.42.0.0/16",

        time: "12:06:40",

        confidence: 61

    },

    {

        id: 2,

        name: "Periodic C2 beacon",

        type: "C2 BEACON",

        severity: "high",

        source: "10.42.7.19",

        destination: "172.16.8.44",

        time: "12:05:21",

        confidence: 94

    },

    {

        id: 3,

        name: "DNS generated-domain pattern",

        type: "DGA TUNNEL",

        severity: "high",

        source: "10.42.5.77",

        destination: "DNS RESOLVER",

        time: "12:04:18",

        confidence: 92

    },

    {

        id: 4,

        name: "Unknown traffic behavior",

        type: "ANOMALY",

        severity: "anomaly",

        source: "10.42.12.8",

        destination: "EXTERNAL",

        time: "12:03:52",

        confidence: 84

    },

    {

        id: 5,

        name: "SYN rate deviation",

        type: "DDoS",

        severity: "critical",

        source: "MULTIPLE",

        destination: "PROTECTED EDGE",

        time: "11:58:09",

        confidence: 97

    }

];


/* =========================================================
   NUMBER ANIMATION
========================================================= */

function animateNumber(
    element,
    target,
    duration = 500
) {

    if (!element) {
        return;
    }

    const start =
        parseInt(
            element.textContent.replace(/,/g, "")
        ) || 0;

    const difference =
        target - start;

    const startTime =
        performance.now();


    function update(currentTime) {

        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(
                elapsed / duration,
                1
            );

        const eased =
            1 - Math.pow(
                1 - progress,
                3
            );

        const value =
            Math.round(
                start +
                difference * eased
            );

        element.textContent =
            value.toLocaleString();


        if (progress < 1) {

            requestAnimationFrame(
                update
            );

        }

    }


    requestAnimationFrame(update);
}


/* =========================================================
   UPDATE DASHBOARD
========================================================= */

function updateDashboard(data) {

    animateNumber(
        packetsEl,
        data.packets
    );

    animateNumber(
        flowsEl,
        data.flows
    );

    animateNumber(
        sourcesEl,
        data.sources
    );

    animateNumber(
        riskScoreEl,
        data.risk
    );

    animateNumber(
        riskCircleEl,
        data.risk
    );


    if (confidenceEl) {

        confidenceEl.textContent =
            `${data.confidence}%`;

    }


    if (confidenceBarEl) {

        confidenceBarEl.style.width =
            `${data.confidence}%`;

    }


    if (riskStatusEl) {

        riskStatusEl.textContent =
            data.status;

    }


    if (currentScenarioEl) {

        currentScenarioEl.innerHTML =
            `<i class="fa-solid fa-circle"></i> ${data.scenario}`;

    }


    if (riskLevelEl) {

        riskLevelEl.textContent =
            data.level;

        riskLevelEl.className =
            "level-badge " +
            getRiskClass(data.level);

    }


    if (riskDescriptionTitleEl) {

        riskDescriptionTitleEl.textContent =
            data.title;

    }


    if (riskDescriptionEl) {

        riskDescriptionEl.textContent =
            data.description;

    }


    if (investigationTitleEl) {

        investigationTitleEl.textContent =
            data.title;

    }


    if (investigationConfidenceEl) {

        investigationConfidenceEl.textContent =
            `${data.confidence}%`;

    }


    if (investigationRouteEl) {

        investigationRouteEl.innerHTML =
            data.route.replace(
                "→",
                '<i class="fa-solid fa-chevron-right"></i>'
            );

    }


    if (selectedTypeEl) {

        selectedTypeEl.textContent =
            data.threat ||
            "RECONNAISSANCE";

    }


    if (data.evidence) {

        if (evidence1El) {

            evidence1El.textContent =
                data.evidence[0];

        }

        if (evidence2El) {

            evidence2El.textContent =
                data.evidence[1];

        }

        if (evidence3El) {

            evidence3El.textContent =
                data.evidence[2];

        }

    }


    if (sessionIdEl) {

        sessionIdEl.textContent =
            generateSessionId();

    }


    if (observedTimeEl) {

        observedTimeEl.textContent =
            getCurrentTime();

    }


    updateRiskCircle(
        data.risk
    );

    updateChart(
        data
    );
}


/* =========================================================
   RISK CLASS
========================================================= */

function getRiskClass(level) {

    if (level === "CRITICAL") {

        return "critical";

    }

    if (level === "HIGH") {

        return "high";

    }

    return "low";
}


/* =========================================================
   RISK CIRCLE
========================================================= */

function updateRiskCircle(risk) {

    let color =
        "#35e68a";


    if (risk >= 90) {

        color =
            "#fb5f6b";

    } else if (risk >= 70) {

        color =
            "#fb923c";

    } else if (risk >= 40) {

        color =
            "#facc15";

    }


    if (
        riskCircleEl &&
        riskCircleEl.parentElement &&
        riskCircleEl.parentElement.parentElement
    ) {

        riskCircleEl.parentElement.parentElement.style.background =
            `conic-gradient(
                ${color} ${risk}%,
                #202630 ${risk}%
            )`;

    }

}


/* =========================================================
   CHART
========================================================= */

function createChart() {

    const canvas =
        document.getElementById(
            "trafficChart"
        );

    if (!canvas) {

        return;

    }

    const ctx =
        canvas.getContext("2d");

    const labels = [];

    const data = [];


    for (
        let i = 0;
        i < 30;
        i++
    ) {

        labels.push(
            `${i}:00`
        );

        data.push(
            26000 +
            Math.random() * 5000
        );

    }


    chart = new Chart(
        ctx,
        {

            type: "line",

            data: {

                labels,

                datasets: [

                    {

                        label:
                            "Packets/sec",

                        data,

                        borderColor:
                            "#22d3ee",

                        backgroundColor:
                            "rgba(34,211,238,0.05)",

                        borderWidth: 1.5,

                        fill: true,

                        tension: 0.35,

                        pointRadius: 0,

                        pointHoverRadius: 3

                    }

                ]

            },

            options: {

                responsive: true,

                maintainAspectRatio: false,

                animation: false,

                plugins: {

                    legend: {

                        display: false

                    }

                },

                scales: {

                    x: {

                        grid: {

                            color:
                                "rgba(255,255,255,0.035)"

                        },

                        ticks: {

                            color:
                                "#68727f",

                            font: {

                                size: 8

                            },

                            maxTicksLimit: 7

                        }

                    },

                    y: {

                        grid: {

                            color:
                                "rgba(255,255,255,0.035)"

                        },

                        ticks: {

                            color:
                                "#68727f",

                            font: {

                                size: 8

                            },

                            callback:
                                value =>
                                    `${Math.round(value / 1000)}k`

                        }

                    }

                }

            }

        }
    );

}


/* =========================================================
   UPDATE CHART
========================================================= */

function updateChart(data) {

    if (!chart) {

        return;

    }

    const current =
        Number(data.packets) || 0;

    const variation =
        current * 0.12;


    chart.data.datasets[0].data =
        chart.data.datasets[0].data.map(
            () => {

                return Math.max(

                    1000,

                    current +
                    (Math.random() - 0.5) *
                    variation

                );

            }
        );


    chart.update(
        "none"
    );

}


/* =========================================================
   BACKEND-DRIVEN LIVE STREAM
========================================================= */

function updateLiveTraffic() {

    if (!streamRunning) {

        return;

    }

    fetchBackendStatus();

}


/* =========================================================
   START LIVE STREAM
========================================================= */

function startLiveStream() {

    clearInterval(
        trafficTimer
    );

    trafficTimer =
        setInterval(
            updateLiveTraffic,
            3000
        );

}


/* =========================================================
   HIGHLIGHT SCENARIO
========================================================= */

function highlightScenario(
    scenarioName
) {

    scenarioButtons.forEach(
        button => {

            button.classList.remove(
                "selected"
            );


            if (
                button.dataset.scenario ===
                scenarioName
            ) {

                button.classList.add(
                    "selected"
                );

            }

        }
    );

}


/* =========================================================
   UPDATE AGENTS
========================================================= */

function updateAgents(
    scenarioName
) {

    const cards =
        document.querySelectorAll(
            ".agent-card"
        );


    cards.forEach(
        card => {

            const progress =
                card.querySelector(
                    ".agent-progress span"
                );

            const confidence =
                card.querySelector(
                    ".agent-confidence strong"
                );


            if (
                !progress ||
                !confidence
            ) {

                return;

            }


            let value =
                8 +
                Math.floor(
                    Math.random() * 14
                );


            if (
                scenarioName === "syn"
            ) {

                value =
                    92 +
                    Math.floor(
                        Math.random() * 7
                    );

            }


            if (
                scenarioName === "c2" &&
                card.innerText.includes(
                    "C2 Beacon"
                )
            ) {

                value = 94;

            }


            if (
                scenarioName === "dga" &&
                card.innerText.includes(
                    "DNS Agent"
                )
            ) {

                value = 91;

            }


            if (
                scenarioName === "anomaly" &&
                card.innerText.includes(
                    "Unknown"
                )
            ) {

                value = 88;

            }


            progress.style.width =
                `${value}%`;

            confidence.textContent =
                `${value}%`;

        }
    );

}


/* =========================================================
   DYNAMIC SCENARIO ALERTS
========================================================= */

const scenarioAlerts = {

    baseline: {

        name: "Low-level recon activity",

        type: "RECONNAISSANCE",

        severity: "low",

        source: "10.42.7.19",

        destination: "10.42.0.0/16",

        confidence: 61

    },


    syn: {

        name: "SYN rate deviation",

        type: "DDoS",

        severity: "critical",

        source: "MULTIPLE",

        destination: "PROTECTED EDGE",

        confidence: 97

    },


    c2: {

        name: "Periodic C2 beacon",

        type: "C2 BEACON",

        severity: "high",

        source: "10.42.7.19",

        destination: "172.16.8.44",

        confidence: 94

    },


    dga: {

        name: "DNS generated-domain pattern",

        type: "DGA TUNNEL",

        severity: "high",

        source: "10.42.5.77",

        destination: "DNS RESOLVER",

        confidence: 92

    },


    anomaly: {

        name: "Unknown traffic behavior",

        type: "ANOMALY",

        severity: "anomaly",

        source: "10.42.12.8",

        destination: "EXTERNAL",

        confidence: 84

    }

};


function renderScenarioAlert(
    scenarioName
) {

    if (!alertsListEl) {

        return;

    }


    const alert =
        scenarioAlerts[
            scenarioName
        ] ||
        scenarioAlerts.baseline;


    alertsListEl.innerHTML = "";


    const card =
        document.createElement("div");


    card.className =
        "alert-card";


    card.dataset.id =
        scenarioName;


    card.innerHTML = `

        <div class="alert-top">

            <div class="alert-name">

                <i
                    class="fa-solid fa-circle"
                    style="
                        color:${getSeverityColor(
                            alert.severity
                        )}
                    "
                ></i>

                ${alert.name}

            </div>


            <span class="
                alert-severity
                severity-${alert.severity}
            ">

                ${alert.severity.toUpperCase()}

            </span>

        </div>


        <div class="alert-meta">

            <span>

                ${alert.source}
                →
                ${alert.destination}

            </span>


            <span>

                LIVE

            </span>


            <span class="alert-confidence">

                ${alert.confidence}%

            </span>

        </div>

    `;


    card.addEventListener(
        "click",
        () => {

            selectAlert(
                alert
            );

        }
    );


    alertsListEl.appendChild(
        card
    );

}


/* =========================================================
   SEVERITY COLOR
========================================================= */

function getSeverityColor(
    severity
) {

    const colors = {

        critical:
            "#fb5f6b",

        high:
            "#fb923c",

        anomaly:
            "#a78bfa",

        low:
            "#35e68a"

    };


    return (
        colors[severity] ||
        "#22d3ee"
    );

}


/* =========================================================
   SELECT ALERT
========================================================= */

function selectAlert(
    alert
) {

    selectedAlert =
        alert;


    if (selectedTypeEl) {

        selectedTypeEl.textContent =
            alert.type;

    }


    if (investigationTitleEl) {

        investigationTitleEl.textContent =
            alert.name;

    }


    if (investigationRouteEl) {

        investigationRouteEl.innerHTML =
            `${alert.source}
            <i class="fa-solid fa-chevron-right"></i>
            ${alert.destination}`;

    }


    if (investigationConfidenceEl) {

        investigationConfidenceEl.textContent =
            `${alert.confidence}%`;

    }


    showToast(
        `${alert.type} signal selected`
    );

}


/* =========================================================
   FILTER ALERTS
========================================================= */

function renderAlerts(
    filter = "all"
) {

    if (!alertsListEl) {

        return;

    }


    const filteredAlerts =
        alerts.filter(
            alert => {

                if (
                    !filter ||
                    filter === "all"
                ) {

                    return true;

                }


                return (
                    alert.severity === filter ||
                    alert.type.toLowerCase() ===
                    filter.toLowerCase()
                );

            }
        );


    alertsListEl.innerHTML = "";


    filteredAlerts.forEach(
        alert => {

            const card =
                document.createElement("div");


            card.className =
                "alert-card";


            card.dataset.id =
                alert.id;


            card.innerHTML = `

                <div class="alert-top">

                    <div class="alert-name">

                        <i
                            class="fa-solid fa-circle"
                            style="
                                color:${getSeverityColor(
                                    alert.severity
                                )}
                            "
                        ></i>

                        ${alert.name}

                    </div>


                    <span class="
                        alert-severity
                        severity-${alert.severity}
                    ">

                        ${alert.severity.toUpperCase()}

                    </span>

                </div>


                <div class="alert-meta">

                    <span>

                        ${alert.source}
                        →
                        ${alert.destination}

                    </span>


                    <span>

                        ${alert.time}

                    </span>


                    <span class="alert-confidence">

                        ${alert.confidence}%

                    </span>

                </div>

            `;


            card.addEventListener(
                "click",
                () => {

                    selectAlert(
                        alert
                    );

                }
            );


            alertsListEl.appendChild(
                card
            );

        }
    );

}


/* =========================================================
   FORENSIC RECORD DISPLAY
========================================================= */

let forensicPanelEl = null;

let lastForensicHash = null;


/* =========================================================
   FORENSIC HISTORY PANEL
========================================================= */

let forensicHistoryPanelEl = null;

let forensicHistoryRecords = [];


/* =========================================================
   CREATE FORENSIC PANEL
========================================================= */

function ensureForensicPanel() {

    if (forensicPanelEl) {

        return forensicPanelEl;

    }


    const investigationPanel =
        document.querySelector(
            ".investigation-panel"
        );


    if (!investigationPanel) {

        return null;

    }


    forensicPanelEl =
        document.createElement("div");


    forensicPanelEl.className =
        "sentinel-forensic-panel";


    forensicPanelEl.style.cssText = `

        margin-top:18px;

        padding:16px;

        border:1px solid
            rgba(34,211,238,0.14);

        border-radius:12px;

        background:
            rgba(10,16,24,0.72);

        box-shadow:
            inset 0 0 24px
            rgba(34,211,238,0.025);

    `;


    investigationPanel.appendChild(
        forensicPanelEl
    );


    return forensicPanelEl;

}


/* =========================================================
   RENDER CURRENT FORENSIC RECORD
========================================================= */

function renderForensicRecord(
    record,
    eventLogged = false
) {

    const panel =
        ensureForensicPanel();


    if (!panel) {

        return;

    }


    if (!record) {

        panel.innerHTML = `

            <div style="
                display:flex;
                align-items:center;
                justify-content:space-between;
                gap:12px;
                margin-bottom:10px;
            ">

                <div style="
                    font-size:11px;
                    letter-spacing:1.4px;
                    font-weight:700;
                    color:#68727f;
                ">

                    FORENSIC RECORD

                </div>


                <span style="
                    font-size:10px;
                    letter-spacing:1px;
                    color:#68727f;
                ">

                    NO ACTIVE EVENT

                </span>

            </div>


            <div style="
                font-size:12px;
                color:#7d8793;
                line-height:1.6;
            ">

                No high-risk forensic event is currently
                being recorded.

            </div>

        `;


        lastForensicHash =
            null;


        return;

    }


    const detection =
        record.detection || {};


    const hash =
        record.hash ||
        "Not available";


    const previousHash =
        record.previous_hash ||
        "Not available";


    const level =
        detection.level ||
        "UNKNOWN";


    const risk =
        Number(
            detection.risk_score ?? 0
        );


    const timestamp =
        record.timestamp
            ? new Date(
                record.timestamp * 1000
            ).toLocaleString(
                "en-GB",
                {
                    hour12: false
                }
            )
            : "Not available";


    const eventStatus =
        eventLogged
            ? "NEW EVENT LOGGED"
            : "STORED EVENT";


    const statusColor =
        eventLogged
            ? "#22d3ee"
            : "#35e68a";


    panel.innerHTML = `

        <div style="
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:12px;
            margin-bottom:14px;
        ">

            <div style="
                font-size:11px;
                letter-spacing:1.4px;
                font-weight:700;
                color:#68727f;
            ">

                FORENSIC RECORD

            </div>


            <span style="
                font-size:10px;
                letter-spacing:1px;
                font-weight:700;
                color:${statusColor};
            ">

                ${eventStatus}

            </span>

        </div>


        <div style="
            display:grid;
            grid-template-columns:
                repeat(3,minmax(0,1fr));
            gap:10px;
            margin-bottom:14px;
        ">


            <div style="
                padding:10px;
                border:1px solid
                    rgba(255,255,255,0.06);
                border-radius:8px;
            ">

                <div style="
                    font-size:9px;
                    color:#68727f;
                    letter-spacing:1px;
                    margin-bottom:5px;
                ">

                    SCENARIO

                </div>


                <strong style="
                    font-size:12px;
                    color:#d9e1e8;
                ">

                    ${(record.scenario || "UNKNOWN")
                        .toUpperCase()}

                </strong>

            </div>


            <div style="
                padding:10px;
                border:1px solid
                    rgba(255,255,255,0.06);
                border-radius:8px;
            ">

                <div style="
                    font-size:9px;
                    color:#68727f;
                    letter-spacing:1px;
                    margin-bottom:5px;
                ">

                    RISK

                </div>


                <strong style="
                    font-size:12px;
                    color:#fb923c;
                ">

                    ${risk}/100 · ${level}

                </strong>

            </div>


            <div style="
                padding:10px;
                border:1px solid
                    rgba(255,255,255,0.06);
                border-radius:8px;
            ">

                <div style="
                    font-size:9px;
                    color:#68727f;
                    letter-spacing:1px;
                    margin-bottom:5px;
                ">

                    CHAIN STATUS

                </div>


                <strong style="
                    font-size:12px;
                    color:#35e68a;
                ">

                    HASH LINKED

                </strong>

            </div>

        </div>


        <div style="
            display:grid;
            gap:9px;
        ">


            <div>

                <div style="
                    font-size:9px;
                    color:#68727f;
                    letter-spacing:1px;
                    margin-bottom:4px;
                ">

                    SHA-256 HASH

                </div>


                <code style="
                    display:block;
                    overflow-wrap:anywhere;
                    font-size:10px;
                    line-height:1.5;
                    color:#22d3ee;
                    background:
                        rgba(34,211,238,0.035);
                    border-radius:7px;
                    padding:8px;
                ">

                    ${hash}

                </code>

            </div>


            <div>

                <div style="
                    font-size:9px;
                    color:#68727f;
                    letter-spacing:1px;
                    margin-bottom:4px;
                ">

                    PREVIOUS HASH

                </div>


                <code style="
                    display:block;
                    overflow-wrap:anywhere;
                    font-size:10px;
                    line-height:1.5;
                    color:#9aa5b1;
                    background:
                        rgba(255,255,255,0.025);
                    border-radius:7px;
                    padding:8px;
                ">

                    ${previousHash}

                </code>

            </div>


            <div style="
                display:flex;
                justify-content:space-between;
                gap:12px;
                padding-top:3px;
                font-size:10px;
                color:#68727f;
            ">

                <span>

                    RECORDED

                </span>


                <span style="
                    color:#9aa5b1;
                ">

                    ${timestamp}

                </span>

            </div>

        </div>

    `;


    if (
        hash !==
        lastForensicHash
    ) {

        lastForensicHash =
            hash;

    }

}


/* =========================================================
   FORENSIC HISTORY
========================================================= */

function ensureForensicHistoryPanel() {

    if (forensicHistoryPanelEl) {

        return forensicHistoryPanelEl;

    }


    const investigationPanel =
        document.querySelector(
            ".investigation-panel"
        );


    if (!investigationPanel) {

        return null;

    }


    forensicHistoryPanelEl =
        document.createElement("div");


    forensicHistoryPanelEl.className =
        "sentinel-forensic-history-panel";


    forensicHistoryPanelEl.style.cssText = `

        margin-top:14px;

        padding:16px;

        border:1px solid
            rgba(167,139,250,0.16);

        border-radius:12px;

        background:
            rgba(10,16,24,0.72);

    `;


    investigationPanel.appendChild(
        forensicHistoryPanelEl
    );


    return forensicHistoryPanelEl;

}


/* =========================================================
   FORMAT FORENSIC TIME
========================================================= */

function formatForensicTime(
    timestamp
) {

    if (!timestamp) {

        return "Unknown";

    }


    return new Date(
        timestamp * 1000
    ).toLocaleString(
        "en-GB",
        {
            hour12: false
        }
    );

}


/* =========================================================
   FORENSIC SEVERITY COLOR
========================================================= */

function getForensicLevelColor(
    level
) {

    if (level === "CRITICAL") {

        return "#fb5f6b";

    }

    if (level === "HIGH") {

        return "#fb923c";

    }

    if (level === "MEDIUM") {

        return "#facc15";

    }

    return "#35e68a";

}


/* =========================================================
   RENDER FORENSIC HISTORY
========================================================= */

function renderForensicHistory(
    records
) {

    const panel =
        ensureForensicHistoryPanel();


    if (!panel) {

        return;

    }


    forensicHistoryRecords =
        Array.isArray(records)
            ? records
            : [];


    if (
        forensicHistoryRecords.length === 0
    ) {

        panel.innerHTML = `

            <div style="
                display:flex;
                align-items:center;
                justify-content:space-between;
                margin-bottom:12px;
            ">

                <div style="
                    font-size:11px;
                    font-weight:700;
                    letter-spacing:1.4px;
                    color:#68727f;
                ">

                    FORENSIC HISTORY

                </div>

                <span style="
                    font-size:10px;
                    color:#68727f;
                ">

                    0 RECORDS

                </span>

            </div>


            <div style="
                font-size:12px;
                color:#7d8793;
            ">

                No persistent forensic records found.

            </div>

        `;

        return;

    }


    let html = `

        <div style="
            display:flex;
            align-items:center;
            justify-content:space-between;
            gap:10px;
            margin-bottom:14px;
        ">

            <div>

                <div style="
                    font-size:11px;
                    font-weight:700;
                    letter-spacing:1.4px;
                    color:#68727f;
                ">

                    FORENSIC HISTORY

                </div>

                <div style="
                    margin-top:4px;
                    font-size:10px;
                    color:#59636e;
                ">

                    Persistent tamper-evident records

                </div>

            </div>


            <span style="
                font-size:10px;
                font-weight:700;
                letter-spacing:1px;
                color:#a78bfa;
            ">

                ${forensicHistoryRecords.length}
                RECORD${forensicHistoryRecords.length === 1 ? "" : "S"}

            </span>

        </div>


        <div style="
            display:grid;
            gap:9px;
        ">
    `;


    forensicHistoryRecords
        .slice()
        .reverse()
        .forEach(
            (record, index) => {

                const detection =
                    record.detection || {};

                const level =
                    detection.level ||
                    "UNKNOWN";

                const risk =
                    Number(
                        detection.risk_score ?? 0
                    );

                const levelColor =
                    getForensicLevelColor(
                        level
                    );

                const scenario =
                    (
                        record.scenario ||
                        "unknown"
                    ).toUpperCase();

                const hash =
                    record.hash ||
                    "Unavailable";

                const previousHash =
                    record.previous_hash ||
                    "Unavailable";

                const shortHash =
                    hash.length > 16
                        ? `${hash.substring(0, 10)}...${hash.substring(hash.length - 6)}`
                        : hash;

                const shortPreviousHash =
                    previousHash.length > 16
                        ? `${previousHash.substring(0, 10)}...${previousHash.substring(previousHash.length - 6)}`
                        : previousHash;


                html += `

                    <div
                        class="sentinel-forensic-history-record"
                        data-index="${index}"
                        style="
                            padding:12px;
                            border:1px solid
                                rgba(255,255,255,0.055);
                            border-radius:9px;
                            background:
                                rgba(255,255,255,0.012);
                        "
                    >

                        <div style="
                            display:flex;
                            justify-content:space-between;
                            align-items:center;
                            gap:10px;
                            margin-bottom:9px;
                        ">

                            <div style="
                                display:flex;
                                align-items:center;
                                gap:8px;
                            ">

                                <span style="
                                    width:7px;
                                    height:7px;
                                    border-radius:50%;
                                    background:${levelColor};
                                    box-shadow:
                                        0 0 8px
                                        ${levelColor};
                                "></span>


                                <strong style="
                                    font-size:11px;
                                    color:#d9e1e8;
                                ">

                                    ${scenario}

                                </strong>

                            </div>


                            <span style="
                                font-size:9px;
                                font-weight:700;
                                letter-spacing:0.8px;
                                color:${levelColor};
                            ">

                                ${level}

                            </span>

                        </div>


                        <div style="
                            display:grid;
                            grid-template-columns:
                                repeat(3,minmax(0,1fr));
                            gap:8px;
                            margin-bottom:9px;
                        ">

                            <div>

                                <div style="
                                    font-size:8px;
                                    color:#59636e;
                                    margin-bottom:3px;
                                    letter-spacing:0.8px;
                                ">

                                    RISK

                                </div>

                                <div style="
                                    font-size:11px;
                                    color:#d9e1e8;
                                ">

                                    ${risk}/100

                                </div>

                            </div>


                            <div>

                                <div style="
                                    font-size:8px;
                                    color:#59636e;
                                    margin-bottom:3px;
                                    letter-spacing:0.8px;
                                ">

                                    HASH

                                </div>

                                <code style="
                                    font-size:9px;
                                    color:#22d3ee;
                                ">

                                    ${shortHash}

                                </code>

                            </div>


                            <div>

                                <div style="
                                    font-size:8px;
                                    color:#59636e;
                                    margin-bottom:3px;
                                    letter-spacing:0.8px;
                                ">

                                    TIME

                                </div>

                                <div style="
                                    font-size:9px;
                                    color:#9aa5b1;
                                ">

                                    ${formatForensicTime(
                                        record.timestamp
                                    )}

                                </div>

                            </div>

                        </div>


                        <div style="
                            font-size:8px;
                            color:#59636e;
                            letter-spacing:0.8px;
                            margin-bottom:3px;
                        ">

                            PREVIOUS HASH

                        </div>


                        <code style="
                            display:block;
                            overflow-wrap:anywhere;
                            font-size:9px;
                            line-height:1.4;
                            color:#7d8793;
                            background:
                                rgba(255,255,255,0.018);
                            padding:6px 7px;
                            border-radius:6px;
                        ">

                            ${shortPreviousHash}

                        </code>

                    </div>

                `;

            }
        );


    html += `

        </div>
    `;


    panel.innerHTML =
        html;

}


/* =========================================================
   FETCH FORENSIC HISTORY
========================================================= */

async function fetchForensicHistory() {

    try {

        const response =
            await fetch(
                `${BACKEND_URL}/api/forensics`,
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Forensic history API error: ${response.status}`
            );

        }


        const data =
            await response.json();


        if (
            data.status ===
            "success"
        ) {

            renderForensicHistory(
                data.records
            );

        }

    } catch (error) {

        console.error(
            "Forensic history loading failed:",
            error
        );

    }

}


/* =========================================================
   VERIFY FORENSIC HASH CHAIN
========================================================= */

async function verifyForensicChain() {

    try {

        const response =
            await fetch(
                `${BACKEND_URL}/api/forensics/verify`,
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Forensic verification API error: ${response.status}`
            );

        }


        const data =
            await response.json();


        if (
            data.valid === true
        ) {

            return true;

        }

        return false;

    } catch (error) {

        console.error(
            "Forensic chain verification failed:",
            error
        );

        return false;

    }

}


/* =========================================================
   FORENSIC HISTORY REFRESH
========================================================= */

async function refreshForensicData() {

    await fetchForensicHistory();

    await verifyForensicChain();

}


/* =========================================================
   FILTER BUTTONS
========================================================= */

filterButtons.forEach(
    button => {

        button.addEventListener(
            "click",
            () => {

                filterButtons.forEach(
                    item =>
                        item.classList.remove(
                            "active"
                        )
                );


                button.classList.add(
                    "active"
                );


                renderAlerts(
                    button.dataset.filter
                );

            }
        );

    }
);


/* =========================================================
   PAUSE / RESUME
========================================================= */

if (pauseBtn) {

    pauseBtn.addEventListener(
        "click",
        () => {

            streamRunning =
                !streamRunning;


            if (streamRunning) {

                pauseBtn.innerHTML = `

                    <i class="fa-solid fa-pause"></i>

                    <span>
                        Pause stream
                    </span>

                `;


                showToast(
                    "Live stream resumed"
                );


                startLiveStream();

                fetchBackendStatus();

            } else {

                pauseBtn.innerHTML = `

                    <i class="fa-solid fa-play"></i>

                    <span>
                        Resume stream
                    </span>

                `;


                showToast(
                    "Live stream paused"
                );

            }

        }
    );

}


/* =========================================================
   INJECT TOP BUTTON
========================================================= */

if (injectTopBtn) {

    injectTopBtn.addEventListener(
        "click",
        () => {

            const names = [

                "syn",

                "c2",

                "dga",

                "anomaly"

            ];


            const randomScenario =
                names[
                    Math.floor(
                        Math.random() *
                        names.length
                    )
                ];


            sendScenarioToBackend(
                randomScenario
            );

        }
    );

}


/* =========================================================
   SCENARIO BUTTONS
========================================================= */

scenarioButtons.forEach(
    button => {

        button.addEventListener(
            "click",
            () => {

                const scenario =
                    button.dataset.scenario;


                sendScenarioToBackend(
                    scenario
                );

            }
        );

    }
);


/* =========================================================
   RESTORE BASELINE
========================================================= */

if (restoreBtn) {

    restoreBtn.addEventListener(
        "click",
        () => {

            sendScenarioToBackend(
                "baseline"
            );

        }
    );

}


/* =========================================================
   TOAST
========================================================= */

let toastTimer = null;


function showToast(
    message
) {

    if (
        !toastEl ||
        !toastMessageEl
    ) {

        return;

    }


    toastMessageEl.textContent =
        message;


    toastEl.classList.add(
        "show"
    );


    clearTimeout(
        toastTimer
    );


    toastTimer =
        setTimeout(
            () => {

                toastEl.classList.remove(
                    "show"
                );

            },
            2600
        );

}


/* =========================================================
   SESSION ID
========================================================= */

function generateSessionId() {

    return (

        "flow_" +

        Math.random()
            .toString(36)
            .substring(2, 8)
            .toUpperCase()

    );

}


/* =========================================================
   TIME
========================================================= */

function getCurrentTime() {

    const now =
        new Date();


    return now.toLocaleTimeString(
        "en-GB",
        {
            hour12: false
        }
    ) + " UTC";

}


/* =========================================================
   APPLY BACKEND STATUS
========================================================= */

function applyBackendStatus(
    data
) {

    const scenarioName =
        data.scenario ||
        "baseline";


    const meta =
        backendScenarioMeta[
            scenarioName
        ] ||
        backendScenarioMeta.baseline;


    const dashboardData = {

        packets:
            Number(
                data.packets_per_second
            ) || 0,

        flows:
            Number(
                data.active_flows
            ) || 0,

        sources:
            Number(
                data.active_sources
            ) || 0,

        risk:
            Number(
                data.risk_score
            ) || 0,

        confidence:
            Number(
                data.confidence
            ) || 0,

        scenario:
            meta.name,

        status:
            meta.status,

        level:
            meta.level,

        title:
            meta.title,

        description:
            meta.description,

        route:
            meta.route,

        threat:
            meta.threat,

        evidence:
            meta.evidence

    };


    currentScenario =
        scenarioName;


    updateDashboard(
        dashboardData
    );


    highlightScenario(
        scenarioName
    );


    updateAgents(
        scenarioName
    );


    renderScenarioAlert(
        scenarioName
    );


    /* ---------------------------------------------
       CURRENT FORENSIC RECORD
    --------------------------------------------- */

    renderForensicRecord(

        data.latest_forensic_record ||
        data.forensic_record ||
        null,

        Boolean(
            data.forensic_event_logged
        )

    );


    /* ---------------------------------------------
       FORENSIC HISTORY
    --------------------------------------------- */

    if (
        data.forensic_event_logged
    ) {

        fetchForensicHistory();

        showToast(
            "New forensic event recorded"
        );

    }


    updateBackendThreatCount(
        Number(
            data.active_threats
        ) || 0
    );

}


/* =========================================================
   ACTIVE THREAT COUNT
========================================================= */

function updateBackendThreatCount(
    count
) {

    if (!activeThreatsEl) {

        return;

    }


    activeThreatsEl.textContent =
        count === 0
            ? "0 active threats"
            : `${count} active threats`;

}


/* =========================================================
   FETCH BACKEND STATUS
========================================================= */

async function fetchBackendStatus() {

    try {

        const response =
            await fetch(
                `${BACKEND_URL}/api/status`,
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                `Backend API error: ${response.status}`
            );

        }


        const data =
            await response.json();


        console.log(
            "SentinelNet Backend:",
            data
        );


        if (
            data.status ===
            "online"
        ) {

            applyBackendStatus(
                data
            );

        }

    } catch (error) {

        console.error(
            "SentinelNet backend connection failed:",
            error
        );

    }

}


/* =========================================================
   SEND SCENARIO TO BACKEND
========================================================= */

async function sendScenarioToBackend(
    scenario
) {

    try {

        const response =
            await fetch(
                `${BACKEND_URL}/api/scenario/${scenario}`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    }
                }
            );


        if (!response.ok) {

            throw new Error(
                `Scenario API error: ${response.status}`
            );

        }


        const data =
            await response.json();


        console.log(
            "Scenario sent to backend:",
            data
        );


        if (
            data.status ===
            "success"
        ) {

            showToast(
                `Scenario: ${scenario.toUpperCase()}`
            );


            highlightScenario(
                scenario
            );


            await fetchBackendStatus();


            /*
             * Refresh forensic history after
             * every scenario change.
             */

            await fetchForensicHistory();

        } else {

            showToast(
                data.message ||
                "Unable to change scenario"
            );

        }

    } catch (error) {

        console.error(
            "Scenario connection failed:",
            error
        );


        showToast(
            "Unable to connect to backend"
        );

    }

}


/* =========================================================
   INITIALIZATION
========================================================= */

function initialize() {

    createChart();


    renderScenarioAlert(
        "baseline"
    );


    renderForensicRecord(
        null,
        false
    );


    ensureForensicHistoryPanel();


    updateDashboard(
        baseline
    );


    startLiveStream();


    showToast(
        "SentinelNet monitoring initialized"
    );

}


/* =========================================================
   START APPLICATION
========================================================= */

initialize();


/* =========================================================
   INITIAL BACKEND LOAD
========================================================= */

fetchBackendStatus();


/* =========================================================
   INITIAL FORENSIC HISTORY LOAD
========================================================= */

fetchForensicHistory();


/* =========================================================
   BACKEND POLLING
========================================================= */

setInterval(
    fetchBackendStatus,
    3000
);


/* =========================================================
   FORENSIC HISTORY POLLING
========================================================= */

setInterval(
    fetchForensicHistory,
    5000
);