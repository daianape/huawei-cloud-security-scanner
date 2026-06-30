"""
Huawei Cloud Security Scanner - HTML Dashboard Report Generator

Generates a static HTML dashboard similar to AWS Service Screener,
with sidebar navigation, severity charts, and detailed findings table.
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

from core.models import Finding, ScanResult, ScanSummary, Severity, Status

logger = logging.getLogger(__name__)


class HTMLReportGenerator:
    """Generates a static HTML dashboard from scan results."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list[ScanResult]) -> str:
        """
        Generate the complete HTML dashboard.
        Returns the path to the generated index.html.
        """
        # Consolidate all findings
        all_findings = []
        all_summaries = []
        for result in results:
            all_findings.extend(result.findings)
            all_summaries.append(result.summary)

        # Build data for the dashboard
        dashboard_data = self._build_dashboard_data(all_findings, all_summaries)

        # Write the data JSON
        data_dir = self.output_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        data_path = data_dir / "scan_results.json"
        with open(data_path, "w", encoding="utf-8") as f:
            json.dump(dashboard_data, f, indent=2, ensure_ascii=False)

        # Generate HTML
        html_content = self._render_html(dashboard_data)
        index_path = self.output_dir / "index.html"
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML dashboard generated: {index_path}")
        return str(index_path)

    def _build_dashboard_data(
        self, findings: list[Finding], summaries: list[ScanSummary]
    ) -> dict:
        """Build structured data for the dashboard."""
        # Count by severity (only failures)
        failed = [f for f in findings if f.status == Status.FAIL]
        severity_counts = {
            "critical": sum(1 for f in failed if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in failed if f.severity == Severity.HIGH),
            "medium": sum(1 for f in failed if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in failed if f.severity == Severity.LOW),
            "informational": sum(
                1 for f in failed if f.severity == Severity.INFORMATIONAL
            ),
        }

        # Count by service
        service_counts = {}
        for f in failed:
            svc = f.service.upper()
            service_counts[svc] = service_counts.get(svc, 0) + 1

        # Count by status
        status_counts = {
            "pass": sum(1 for f in findings if f.status == Status.PASS),
            "fail": sum(1 for f in findings if f.status == Status.FAIL),
            "error": sum(1 for f in findings if f.status == Status.ERROR),
        }

        # Findings by service for detail pages
        findings_by_service = {}
        for f in findings:
            svc = f.service.upper()
            if svc not in findings_by_service:
                findings_by_service[svc] = []
            findings_by_service[svc].append(f.to_dict())

        # Account info
        accounts = []
        for s in summaries:
            accounts.append({
                "name": s.account_name,
                "id": s.account_id,
                "region": s.region,
            })

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "total_failed": len(failed),
            "total_passed": status_counts["pass"],
            "total_errors": status_counts["error"],
            "severity_counts": severity_counts,
            "service_counts": service_counts,
            "status_counts": status_counts,
            "accounts": accounts,
            "services_scanned": list(findings_by_service.keys()),
            "findings_by_service": findings_by_service,
            "findings": [f.to_dict() for f in findings],
        }

    def _render_html(self, data: dict) -> str:
        """Render the complete HTML dashboard."""
        findings_json = json.dumps(data, ensure_ascii=False)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Huawei Cloud Security Scanner | Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
{self._get_css()}
    </style>
</head>
<body>
    <div class="layout">
        <!-- Sidebar -->
        <nav class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <span class="logo-icon">&#x1F6E1;</span>
                    <span class="logo-text">HWCloud Scanner</span>
                </div>
            </div>
            <ul class="nav-menu">
                <li class="nav-item active" data-page="home">
                    <span class="nav-icon">&#x1F3E0;</span>
                    <span>Home</span>
                </li>
                <li class="nav-section">Pages</li>
                <li class="nav-item" data-page="findings">
                    <span class="nav-icon">&#x1F50D;</span>
                    <span>FINDINGS</span>
                </li>
            </ul>
            <ul class="nav-menu" id="services-nav">
                <li class="nav-section">Services</li>
            </ul>
        </nav>

        <!-- Main Content -->
        <main class="main-content">
            <header class="top-bar">
                <button class="menu-toggle" onclick="toggleSidebar()">&#9776;</button>
                <span class="breadcrumb" id="breadcrumb">Home / INDEX</span>
                <div class="account-selector">
                    <select id="account-filter" onchange="filterByAccount()">
                        <option value="all">All Accounts</option>
                    </select>
                </div>
            </header>

            <!-- Home Page -->
            <div class="page active" id="page-home">
                <h1>INDEX</h1>
                <div class="dashboard-grid">
                    <div class="severity-card">
                        <div class="severity-header">No. Criticality</div>
                        <div class="severity-body" id="severity-bars"></div>
                    </div>
                    <div class="summary-card" id="summary-card">
                        <div class="summary-number" id="total-failed">0</div>
                        <div class="summary-label">Security Findings</div>
                    </div>
                </div>
                <div class="service-cards" id="service-cards"></div>
                <div class="charts-row">
                    <div class="chart-container">
                        <h3>Findings by Severity</h3>
                        <canvas id="severityChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <h3>Findings by Service</h3>
                        <canvas id="serviceChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Findings Page -->
            <div class="page" id="page-findings">
                <h1>All Findings</h1>
                <div class="filters-bar">
                    <select id="filter-severity" onchange="applyFilters()">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                    <select id="filter-status" onchange="applyFilters()">
                        <option value="all">All Status</option>
                        <option value="fail">Failed</option>
                        <option value="pass">Passed</option>
                    </select>
                    <select id="filter-service" onchange="applyFilters()">
                        <option value="all">All Services</option>
                    </select>
                </div>
                <div class="table-container">
                    <table class="findings-table" id="findings-table">
                        <thead>
                            <tr>
                                <th>Service</th>
                                <th>Check ID</th>
                                <th>Status</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>Resource</th>
                                <th>Remediation</th>
                            </tr>
                        </thead>
                        <tbody id="findings-tbody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Service Detail Pages (dynamically created) -->
            <div class="page" id="page-service-detail">
                <h1 id="service-detail-title">Service</h1>
                <div class="table-container">
                    <table class="findings-table">
                        <thead>
                            <tr>
                                <th>Check ID</th>
                                <th>Status</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>Resource</th>
                                <th>Remediation</th>
                            </tr>
                        </thead>
                        <tbody id="service-findings-tbody"></tbody>
                    </table>
                </div>
            </div>
        </main>
    </div>

    <script>
const SCAN_DATA = {findings_json};
{self._get_javascript()}
    </script>
</body>
</html>"""

    def _get_css(self) -> str:
        """Return CSS styles for the dashboard."""
        return """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; color: #2c3e50; }
.layout { display: flex; min-height: 100vh; }

/* Sidebar */
.sidebar { width: 250px; background: #1e272e; color: #fff; position: fixed; height: 100vh; overflow-y: auto; transition: transform 0.3s; z-index: 1000; }
.sidebar-header { padding: 20px; border-bottom: 1px solid #34495e; }
.logo { display: flex; align-items: center; gap: 10px; }
.logo-icon { font-size: 24px; }
.logo-text { font-size: 16px; font-weight: bold; color: #e74c3c; }
.nav-menu { list-style: none; padding: 10px 0; }
.nav-section { padding: 10px 20px 5px; font-size: 11px; text-transform: uppercase; color: #7f8c8d; letter-spacing: 1px; }
.nav-item { padding: 10px 20px; cursor: pointer; display: flex; align-items: center; gap: 10px; transition: background 0.2s; font-size: 14px; }
.nav-item:hover { background: #34495e; }
.nav-item.active { background: #2980b9; }
.nav-icon { font-size: 16px; }

/* Main Content */
.main-content { margin-left: 250px; flex: 1; padding: 0; min-height: 100vh; }
.top-bar { display: flex; align-items: center; justify-content: space-between; padding: 15px 30px; background: #fff; border-bottom: 1px solid #ddd; position: sticky; top: 0; z-index: 100; }
.menu-toggle { display: none; background: none; border: none; font-size: 24px; cursor: pointer; }
.breadcrumb { font-size: 14px; color: #7f8c8d; }
.account-selector select { padding: 6px 12px; border: 1px solid #ddd; border-radius: 4px; }

/* Pages */
.page { display: none; padding: 30px; }
.page.active { display: block; }
.page h1 { margin-bottom: 20px; font-size: 24px; }

/* Dashboard Grid */
.dashboard-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-bottom: 20px; }
.severity-card { background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.severity-header { background: #e74c3c; color: #fff; padding: 12px 20px; font-weight: bold; font-size: 14px; }
.severity-body { padding: 20px; }
.severity-row { display: flex; align-items: center; margin-bottom: 12px; }
.severity-icon { width: 24px; font-size: 16px; }
.severity-label { width: 100px; font-size: 14px; font-weight: 500; }
.severity-bar-container { flex: 1; height: 24px; background: #ecf0f1; border-radius: 4px; margin: 0 10px; overflow: hidden; }
.severity-bar { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 11px; color: #fff; font-weight: bold; min-width: fit-content; }
.severity-count { width: 40px; text-align: right; font-weight: bold; }

.summary-card { background: #2c3e50; color: #fff; border-radius: 8px; padding: 30px; text-align: center; display: flex; flex-direction: column; justify-content: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.summary-number { font-size: 64px; font-weight: bold; }
.summary-label { font-size: 16px; margin-top: 10px; opacity: 0.8; }

/* Service Cards */
.service-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
.svc-card { background: #fff; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer; transition: transform 0.2s; border-top: 4px solid; }
.svc-card:hover { transform: translateY(-2px); }
.svc-card-count { font-size: 32px; font-weight: bold; color: #2c3e50; }
.svc-card-name { font-size: 12px; color: #7f8c8d; margin-top: 5px; text-transform: uppercase; }
.svc-card-breakdown { font-size: 11px; margin-top: 8px; color: #95a5a6; }

/* Charts */
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
.chart-container { background: #fff; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.chart-container h3 { margin-bottom: 15px; font-size: 16px; }

/* Filters */
.filters-bar { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
.filters-bar select { padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }

/* Tables */
.table-container { overflow-x: auto; }
.findings-table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.findings-table th { background: #2c3e50; color: #fff; padding: 12px 15px; text-align: left; font-size: 13px; }
.findings-table td { padding: 10px 15px; border-bottom: 1px solid #ecf0f1; font-size: 13px; vertical-align: top; }
.findings-table tr:hover { background: #f8f9fa; }

/* Status badges */
.badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
.badge-fail { background: #e74c3c; color: #fff; }
.badge-pass { background: #27ae60; color: #fff; }
.badge-error { background: #f39c12; color: #fff; }
.badge-critical { background: #8e44ad; color: #fff; }
.badge-high { background: #e74c3c; color: #fff; }
.badge-medium { background: #f39c12; color: #fff; }
.badge-low { background: #f1c40f; color: #333; }
.badge-informational { background: #3498db; color: #fff; }

/* Responsive */
@media (max-width: 768px) {
    .sidebar { transform: translateX(-100%); }
    .sidebar.open { transform: translateX(0); }
    .main-content { margin-left: 0; }
    .menu-toggle { display: block; }
    .dashboard-grid { grid-template-columns: 1fr; }
    .charts-row { grid-template-columns: 1fr; }
}
"""

    def _get_javascript(self) -> str:
        """Return JavaScript for dashboard interactivity."""
        return """
// Initialize Dashboard
document.addEventListener('DOMContentLoaded', function() {
    initDashboard();
});

function initDashboard() {
    renderSeverityBars();
    renderSummaryCard();
    renderServiceCards();
    renderCharts();
    renderFindingsTable(SCAN_DATA.findings);
    populateFilters();
    populateServicesNav();
    populateAccountFilter();
}

function renderSeverityBars() {
    const container = document.getElementById('severity-bars');
    const counts = SCAN_DATA.severity_counts;
    const total = SCAN_DATA.total_failed || 1;

    const severities = [
        { key: 'critical', label: 'Critical', icon: '&#x26D4;', color: '#8e44ad' },
        { key: 'high', label: 'High', icon: '&#x1F6AB;', color: '#e74c3c' },
        { key: 'medium', label: 'Medium', icon: '&#x26A0;', color: '#f39c12' },
        { key: 'low', label: 'Low', icon: '&#x1F441;', color: '#f1c40f' },
        { key: 'informational', label: 'Info', icon: '&#x2139;', color: '#3498db' },
    ];

    let html = '';
    severities.forEach(s => {
        const count = counts[s.key] || 0;
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        html += `
            <div class="severity-row">
                <span class="severity-icon">${s.icon}</span>
                <span class="severity-label">${s.label}</span>
                <div class="severity-bar-container">
                    <div class="severity-bar" style="width: ${Math.max(pct, 2)}%; background: ${s.color};">
                        (${pct}%)
                    </div>
                </div>
                <span class="severity-count">${count}</span>
            </div>`;
    });
    container.innerHTML = html;
}

function renderSummaryCard() {
    document.getElementById('total-failed').textContent = SCAN_DATA.total_failed;
}

function renderServiceCards() {
    const container = document.getElementById('service-cards');
    const colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c'];
    let html = '';
    let i = 0;

    Object.entries(SCAN_DATA.service_counts).forEach(([service, count]) => {
        const color = colors[i % colors.length];
        const serviceFindings = SCAN_DATA.findings_by_service[service] || [];
        const passed = serviceFindings.filter(f => f.status === 'pass').length;
        const failed = serviceFindings.filter(f => f.status === 'fail').length;

        html += `
            <div class="svc-card" style="border-top-color: ${color}" onclick="showServiceDetail('${service}')">
                <div class="svc-card-count">${failed}</div>
                <div class="svc-card-name">${service}</div>
                <div class="svc-card-breakdown">
                    &#x2705; ${passed} passed &nbsp; &#x274C; ${failed} failed
                </div>
            </div>`;
        i++;
    });
    container.innerHTML = html;
}

function renderCharts() {
    // Severity Pie Chart
    const sevCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(sevCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: [
                    SCAN_DATA.severity_counts.critical,
                    SCAN_DATA.severity_counts.high,
                    SCAN_DATA.severity_counts.medium,
                    SCAN_DATA.severity_counts.low,
                    SCAN_DATA.severity_counts.informational,
                ],
                backgroundColor: ['#8e44ad', '#e74c3c', '#f39c12', '#f1c40f', '#3498db'],
            }]
        },
        options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });

    // Service Bar Chart
    const svcCtx = document.getElementById('serviceChart').getContext('2d');
    const services = Object.keys(SCAN_DATA.service_counts);
    const svcData = services.map(s => SCAN_DATA.service_counts[s]);
    new Chart(svcCtx, {
        type: 'bar',
        data: {
            labels: services,
            datasets: [{
                label: 'Failed Checks',
                data: svcData,
                backgroundColor: '#e74c3c',
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
        }
    });
}

function renderFindingsTable(findings) {
    const tbody = document.getElementById('findings-tbody');
    let html = '';

    findings.forEach(f => {
        const statusClass = 'badge-' + f.status;
        const sevClass = 'badge-' + f.severity;
        html += `<tr>
            <td>${f.service.toUpperCase()}</td>
            <td>${f.check_id}</td>
            <td><span class="badge ${statusClass}">${f.status}</span></td>
            <td><span class="badge ${sevClass}">${f.severity}</span></td>
            <td>${f.description}</td>
            <td>${f.resource_name || f.resource_id || '-'}</td>
            <td>${f.remediation || '-'}</td>
        </tr>`;
    });
    tbody.innerHTML = html || '<tr><td colspan="7">No findings</td></tr>';
}

function populateFilters() {
    const serviceFilter = document.getElementById('filter-service');
    SCAN_DATA.services_scanned.forEach(s => {
        const opt = document.createElement('option');
        opt.value = s.toLowerCase();
        opt.textContent = s;
        serviceFilter.appendChild(opt);
    });
}

function populateServicesNav() {
    const nav = document.getElementById('services-nav');
    SCAN_DATA.services_scanned.forEach(s => {
        const li = document.createElement('li');
        li.className = 'nav-item';
        li.setAttribute('data-page', 'service-' + s.toLowerCase());
        li.innerHTML = `<span class="nav-icon">&#x2699;</span><span>${s}</span>`;
        li.onclick = () => showServiceDetail(s);
        nav.appendChild(li);
    });
}

function populateAccountFilter() {
    const select = document.getElementById('account-filter');
    SCAN_DATA.accounts.forEach(a => {
        const opt = document.createElement('option');
        opt.value = a.id || a.name;
        opt.textContent = `${a.name} (${a.id || 'N/A'})`;
        select.appendChild(opt);
    });
}

function applyFilters() {
    const severity = document.getElementById('filter-severity').value;
    const status = document.getElementById('filter-status').value;
    const service = document.getElementById('filter-service').value;

    let filtered = SCAN_DATA.findings;
    if (severity !== 'all') filtered = filtered.filter(f => f.severity === severity);
    if (status !== 'all') filtered = filtered.filter(f => f.status === status);
    if (service !== 'all') filtered = filtered.filter(f => f.service.toLowerCase() === service);

    renderFindingsTable(filtered);
}

function filterByAccount() {
    const accountId = document.getElementById('account-filter').value;
    if (accountId === 'all') {
        renderFindingsTable(SCAN_DATA.findings);
    } else {
        const filtered = SCAN_DATA.findings.filter(
            f => f.account_id === accountId || f.account_name === accountId
        );
        renderFindingsTable(filtered);
    }
}

// Navigation
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const page = document.getElementById('page-' + pageId);
    if (page) page.classList.add('active');

    const navItem = document.querySelector(`[data-page="${pageId}"]`);
    if (navItem) navItem.classList.add('active');

    document.getElementById('breadcrumb').textContent = 'Home / ' + pageId.toUpperCase();
}

function showServiceDetail(service) {
    showPage('service-detail');
    document.getElementById('service-detail-title').textContent = service + ' Findings';
    document.getElementById('breadcrumb').textContent = 'Home / Services / ' + service;

    const findings = SCAN_DATA.findings_by_service[service] || [];
    const tbody = document.getElementById('service-findings-tbody');
    let html = '';
    findings.forEach(f => {
        html += `<tr>
            <td>${f.check_id}</td>
            <td><span class="badge badge-${f.status}">${f.status}</span></td>
            <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
            <td>${f.description}</td>
            <td>${f.resource_name || f.resource_id || '-'}</td>
            <td>${f.remediation || '-'}</td>
        </tr>`;
    });
    tbody.innerHTML = html || '<tr><td colspan="6">No findings</td></tr>';
}

document.querySelectorAll('.nav-item[data-page]').forEach(item => {
    item.addEventListener('click', () => showPage(item.dataset.page));
});

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}
"""
