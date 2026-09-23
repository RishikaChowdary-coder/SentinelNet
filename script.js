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

const riskStatusEl = document.getElementById("riskStatus");
const riskLevelEl = document.getElementById("riskLevel");

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

    ]

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

function animateNumber(element, target, duration = 500) {

    const start =
        parseInt(
            element.textContent.replace(/,/g, "")
        ) || 0;

    const difference = target - start;

    const startTime = performance.now();


    function update(currentTime) {

        const elapsed =
            currentTime - startTime;

        const progress =
            Math.min(elapsed / duration, 1);

        const eased =
            1 - Math.pow(1 - progress, 3);

        const value =
            Math.round(
                start + difference * eased
            );

        element.textContent =
            value.toLocaleString();


        if (progress < 1) {

            requestAnimationFrame(update);

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


    confidenceEl.textContent =
        `${data.confidence}%`;

    confidenceBarEl.style.width =
        `${data.confidence}%`;


    riskStatusEl.textContent =
        data.status;

    currentScenarioEl.innerHTML =
        `<i class="fa-solid fa-circle"></i> ${data.scenario}`;


    riskLevelEl.textContent =
        data.level;


    riskLevelEl.className =
        "level-badge " +
        getRiskClass(data.level);


    riskDescriptionTitleEl.textContent =
        data.title;


    riskDescriptionEl.textContent =
        data.description;


    investigationTitleEl.textContent =
        data.title;


    investigationConfidenceEl.textContent =
        `${data.confidence}%`;


    investigationRouteEl.innerHTML =
        data.route.replace(
            "→",
            '<i class="fa-solid fa-chevron-right"></i>'
        );


    selectedTypeEl.textContent =
        data.threat ||
        "RECONNAISSANCE";


    evidence1El.textContent =
        data.evidence[0];

    evidence2El.textContent =
        data.evidence[1];

    evidence3El.textContent =
        data.evidence[2];


    sessionIdEl.textContent =
        generateSessionId();


    observedTimeEl.textContent =
        getCurrentTime();


    activeThreatsEl.textContent =
        data.risk > 50
            ? `${Math.ceil(data.risk / 20)} active threats`
            : "0 active threats";


    updateRiskCircle(data.risk);

    updateChart(data);

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


    riskCircleEl.parentElement.parentElement.style
        .background =
        `conic-gradient(
            ${color} ${risk}%,
            #202630 ${risk}%
        )`;

}


/* =========================================================
   CHART
========================================================= */

function createChart() {

    const canvas =
        document.getElementById("trafficChart");


    const ctx =
        canvas.getContext("2d");


    const labels = [];

    const data = [];


    for (let i = 0; i < 30; i++) {

        labels.push(
            `${i}:00`
        );

        data.push(
            26000 +
            Math.random() * 5000
        );

    }


    chart = new Chart(ctx, {

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

    });

}


/* =========================================================
   UPDATE CHART
========================================================= */

function updateChart(data) {

    if (!chart) {
        return;
    }


    const current =
        data.packets;


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


    chart.update("none");

}


/* =========================================================
   SIMULATED LIVE STREAM
========================================================= */

function updateLiveTraffic() {

    if (!streamRunning) {
        return;
    }


    if (currentScenario !== "baseline") {

        const scenario =
            scenarios[currentScenario];

        updateDashboard({

            ...scenario,

            scenario:
                scenario.name

        });

        return;
    }


    const liveData = {

        ...baseline,

        packets:
            27000 +
            Math.floor(
                Math.random() * 3500
            ),

        flows:
            370 +
            Math.floor(
                Math.random() * 45
            ),

        sources:
            115 +
            Math.floor(
                Math.random() * 30
            )

    };


    updateDashboard(liveData);

}


/* =========================================================
   START LIVE STREAM
========================================================= */

function startLiveStream() {

    clearInterval(trafficTimer);


    trafficTimer =
        setInterval(
            updateLiveTraffic,
            2500
        );

}


/* =========================================================
   SCENARIO SELECTION
========================================================= */

function activateScenario(
    scenarioName
) {

    const data =
        scenarios[scenarioName];


    if (!data) {
        return;
    }


    currentScenario =
        scenarioName;


    updateDashboard({

        ...data,

        scenario:
            data.name

    });


    showToast(
        `${data.name} scenario injected`
    );


    highlightScenario(
        scenarioName
    );


    updateAgents(
        scenarioName
    );


    renderAlerts(
        "all"
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


    cards.forEach(card => {

        const progress =
            card.querySelector(
                ".agent-progress span"
            );

        const confidence =
            card.querySelector(
                ".agent-confidence strong"
            );


        if (!progress || !confidence) {
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

    });

}


/* =========================================================
   RESTORE BASELINE
========================================================= */

function restoreBaseline() {

    currentScenario =
        "baseline";


    highlightScenario(
        "baseline"
    );


    updateDashboard(
        baseline
    );


    updateAgents(
        "baseline"
    );


    showToast(
        "Traffic restored to baseline"
    );


    renderAlerts(
        "all"
    );

}


/* =========================================================
   ALERT RENDERING
========================================================= */

function renderAlerts(
    filter = "all"
) {

    alertsListEl.innerHTML = "";


    let filtered =
        alerts;


    if (filter !== "all") {

        filtered =
            alerts.filter(
                alert =>
                    alert.severity ===
                    filter
            );

    }


    filtered.forEach(
        alert => {

            const card =
                document.createElement(
                    "div"
                );


            card.className =
                "alert-card";


            card.dataset.id =
                alert.id;


            card.innerHTML = `

                <div class="alert-top">

                    <div class="alert-name">

                        <i class="fa-solid fa-circle"
                           style="
                               color:${getSeverityColor(alert.severity)}
                           ">
                        </i>

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
                () =>
                    selectAlert(alert)
            );


            alertsListEl.appendChild(
                card
            );

        }
    );

}


/* =========================================================
   SEVERITY COLOR
========================================================= */

function getSeverityColor(
    severity
) {

    const colors = {

        critical: "#fb5f6b",

        high: "#fb923c",

        anomaly: "#a78bfa",

        low: "#35e68a"

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


    selectedTypeEl.textContent =
        alert.type;


    investigationTitleEl.textContent =
        alert.name;


    investigationRouteEl.innerHTML =
        `${alert.source}
        <i class="fa-solid fa-chevron-right"></i>
        ${alert.destination}`;


    investigationConfidenceEl.textContent =
        `${alert.confidence}%`;


    showToast(
        `${alert.type} signal selected`
    );

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
   SCENARIO BUTTONS
========================================================= */

scenarioButtons.forEach(
    button => {

        button.addEventListener(
            "click",
            () => {

                activateScenario(
                    button.dataset.scenario
                );

            }
        );

    }
);


/* =========================================================
   RESTORE BUTTON
========================================================= */

restoreBtn.addEventListener(
    "click",
    restoreBaseline
);


/* =========================================================
   PAUSE / RESUME
========================================================= */

pauseBtn.addEventListener(
    "click",
    () => {

        streamRunning =
            !streamRunning;


        if (streamRunning) {

            pauseBtn.innerHTML = `
                <i class="fa-solid fa-pause"></i>
                <span>Pause stream</span>
            `;


            showToast(
                "Live stream resumed"
            );


            startLiveStream();

        } else {

            pauseBtn.innerHTML = `
                <i class="fa-solid fa-play"></i>
                <span>Resume stream</span>
            `;


            showToast(
                "Live stream paused"
            );

        }

    }
);


/* =========================================================
   INJECT TOP BUTTON
========================================================= */

injectTopBtn.addEventListener(
    "click",
    () => {

        const names =
            [
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


        activateScenario(
            randomScenario
        );

    }
);


/* =========================================================
   TOAST
========================================================= */

let toastTimer = null;


function showToast(
    message
) {

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
   INITIALIZATION
========================================================= */

function initialize() {

    createChart();

    renderAlerts(
        "all"
    );

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
// ===============================
// BACKEND API CONNECTION
// ===============================

async function fetchBackendStatus() {
    try {
        const response = await fetch(
            "http://127.0.0.1:8000/api/status"
        );

        const data = await response.json();

        console.log("SentinelNet Backend:", data);

        updateBackendData(data);

    } catch (error) {
        console.error("Backend connection failed:", error);
    }
}


function updateBackendData(data) {

    // Find KPI cards by their existing text
    const cards = document.querySelectorAll(".kpi-card");

    if (cards.length >= 4) {

        // Packets/sec
        const packets = cards[0].querySelector(".kpi-value");

        if (packets) {
            packets.textContent =
                data.packets_per_second.toLocaleString();
        }

        // Active flows
        const flows = cards[1].querySelector(".kpi-value");

        if (flows) {
            flows.textContent =
                data.active_flows.toLocaleString();
        }

        // Risk score
        const risk = cards[2].querySelector(".kpi-value");

        if (risk) {
            risk.textContent = data.risk_score + "/100";
        }
    }
}


// Get data immediately
fetchBackendStatus();

// Get new data every 3 seconds
setInterval(fetchBackendStatus, 3000);
initialize();