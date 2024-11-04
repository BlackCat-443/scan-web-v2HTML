const urlInput = document.getElementById('urlInput');
const toggleButton = document.getElementById('toggleButton');
const statusLabel = document.getElementById('statusLabel');
const saveButton = document.getElementById('saveButton');
const requestsCtx = document.getElementById('requestsChart').getContext('2d');
const responseTimeCtx = document.getElementById('responseTimeChart').getContext('2d');

// Menu Toggle Functionality
const menuToggle = document.querySelector('.menu-toggle');
const sidebar = document.querySelector('.sidebar');

menuToggle.addEventListener('click', () => {
    sidebar.classList.toggle('expanded');
});

// Close sidebar when clicking outside on mobile
document.addEventListener('click', (e) => {
    if (e.target !== sidebar && e.target !== menuToggle) {
        sidebar.classList.remove('expanded');
    }
});

let monitoring = false;
let url = '';
let requestCounts = [];
let responseTimes = [];
let totalRequests = 0;
const suspiciousThreshold = 50;
let monitoringInterval;

const ATTACK_THRESHOLDS = {
    ddos: { requestsPerSecond: 50, responseTime: 2 },
    bruteForce: { failedLogins: 10, timeWindow: 60 },
    sqlInjection: { suspiciousPatterns: ['SELECT', 'UNION', 'DROP', '--'], threshold: 3 },
    xss: { suspiciousPatterns: ['<script>', 'javascript:', 'onerror='], threshold: 3 }
};

let attackMetrics = {
    failedRequests: 0,
    suspiciousPatterns: 0,
    lastRequestTimestamps: [],
    suspiciousUrls: []
};

// Chart configurations
const requestsChart = new Chart(requestsCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Requests per Second',
            data: [],
            borderColor: 'rgb(255, 99, 132)',
            tension: 0.1
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true,
                max: 100
            }
        }
    }
});

const responseTimeChart = new Chart(responseTimeCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: 'Response Time (seconds)',
            data: [],
            borderColor: 'rgb(75, 192, 192)',
            tension: 0.1
        }]
    },
    options: {
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

function makeRequest() {
    return new Promise((resolve) => {
        const startTime = performance.now();
        setTimeout(() => {
            const endTime = performance.now();
            resolve([1, (endTime - startTime) / 1000]);
        }, Math.random() * 1000);
    });
}

async function monitorTraffic() {
    let successfulRequests = 0;
    let totalResponseTime = 0;

    for (let i = 0; i < 10; i++) {
        const [success, responseTime] = await makeRequest();
        successfulRequests += success;
        totalResponseTime += responseTime;
    }

    const randomRequests = Math.floor(Math.random() * 40) + 10;
    requestCounts.push(randomRequests);
    if (requestCounts.length > 60) requestCounts.shift();

    const avgResponseTime = successfulRequests > 0 ? totalResponseTime / 10 : 0;
    responseTimes.push(avgResponseTime);
    if (responseTimes.length > 60) responseTimes.shift();

    totalRequests += successfulRequests;

    const avgRequests = requestCounts.reduce((a, b) => a + b, 0) / requestCounts.length;
    const status = avgRequests < suspiciousThreshold ? "Normal" : "WARNING";

    statusLabel.textContent = `Status: ${status} | Requests: ${avgRequests.toFixed(2)}/s | Avg Response: ${avgResponseTime.toFixed(3)}s | Total: ${totalRequests}`;
    statusLabel.className = `alert ${status === "Normal" ? "alert-success" : "alert-warning"}`;

    updateCharts();

    const requestData = {
        url: url,
        responseTime: avgResponseTime
    };

    attackMetrics.lastRequestTimestamps.push(Date.now());
    if (attackMetrics.lastRequestTimestamps.length > 100) attackMetrics.lastRequestTimestamps.shift();

    const detectedAttacks = detectAttacks(requestData);
    if (detectedAttacks.length > 0) {
        showAttackAlert(detectedAttacks);
    }
}

function detectAttacks(requestData) {
    let detectedAttacks = [];

    // DDoS Detection
    const recentRequests = attackMetrics.lastRequestTimestamps.filter(t => Date.now() - t < 1000).length;
    if (recentRequests > ATTACK_THRESHOLDS.ddos.requestsPerSecond || 
        requestData.responseTime > ATTACK_THRESHOLDS.ddos.responseTime) {
        detectedAttacks.push("DDoS");
    }

    // Brute Force Detection
    if (attackMetrics.failedRequests > ATTACK_THRESHOLDS.bruteForce.failedLogins) {
        detectedAttacks.push("Brute Force");
    }

    // SQL Injection Detection
    if (ATTACK_THRESHOLDS.sqlInjection.suspiciousPatterns.some(pattern => 
        requestData.url.toLowerCase().includes(pattern.toLowerCase()))) {
        attackMetrics.suspiciousPatterns++;
        if (attackMetrics.suspiciousPatterns >= ATTACK_THRESHOLDS.sqlInjection.threshold) {
            detectedAttacks.push("SQL Injection");
        }
    }

    // XSS Detection
    if (ATTACK_THRESHOLDS.xss.suspiciousPatterns.some(pattern => 
        requestData.url.toLowerCase().includes(pattern.toLowerCase()))) {
        attackMetrics.suspiciousPatterns++;
        if (attackMetrics.suspiciousPatterns >= ATTACK_THRESHOLDS.xss.threshold) {
            detectedAttacks.push("Cross-Site Scripting (XSS)");
        }
    }

    console.log("Detected Attacks:", detectedAttacks); // Tambahkan ini
    return detectedAttacks;
}

function showAttackAlert(attacks) {
    Swal.fire({
        title: 'WARNING!',
        text: `Possible ${attacks.join(", ")} attack(s) detected!`,
        icon: 'warning',
        confirmButtonText: 'OK'
    });
}


function updateCharts() {
    const labels = [...Array(requestCounts.length).keys()];

    requestsChart.data.labels = labels;
    requestsChart.data.datasets[0].data = requestCounts;
    requestsChart.update();

    responseTimeChart.data.labels = labels;
    responseTimeChart.data.datasets[0].data = responseTimes;
    responseTimeChart.update();
}

function saveReport() {
    html2canvas(document.body).then(canvas => {
        const link = document.createElement('a');
        link.download = 'traffic_report.png';
        link.href = canvas.toDataURL();
        link.click();
    });
}

toggleButton.addEventListener('click', () => {
    if (!monitoring) {
        url = urlInput.value;
        if (!url) {
            statusLabel.textContent = "Please enter a valid URL";
            statusLabel.className = "alert alert-danger";
            return;
        }

        monitoring = true;
        toggleButton.textContent = "Stop Monitoring";
        toggleButton.className = "btn btn-danger";
        saveButton.classList.add('d-none');
        monitoringInterval = setInterval (monitorTraffic, 1000);
        attackMetrics = {
            failedRequests: 0,
            suspiciousPatterns: 0,
            lastRequestTimestamps: [],
            suspiciousUrls: []
        };
    } else {
        monitoring = false;
        toggleButton.textContent = "Start Monitoring";
        toggleButton.className = "btn btn-primary";
        saveButton.classList.remove('d-none');
        clearInterval(monitoringInterval);
        const warningDiv = document.querySelector('.alert-danger');
        if (warningDiv) warningDiv.remove();
    }
});

saveButton.addEventListener('click', saveReport);