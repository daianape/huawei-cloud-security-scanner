"""
Huawei Cloud Security Scanner - HTML Dashboard Report Generator

Generates a static HTML dashboard styled like AWS Service Screener,
with dark navy sidebar navigation, yellow-gold section headers,
colored KPI stat cards, and detailed findings tables.
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
        all_findings = []
        all_summaries = []
        for result in results:
            all_findings.extend(result.findings)
            all_summaries.append(result.summary)

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
        service_counts = {}
        for f in failed:
            svc = f.service.upper()
            service_counts[svc] = service_counts.get(svc, 0) + 1
        status_counts = {
            "pass": sum(1 for f in findings if f.status == Status.PASS),
            "fail": sum(1 for f in findings if f.status == Status.FAIL),
            "error": sum(1 for f in findings if f.status == Status.ERROR),
        }
        findings_by_service = {}
        for f in findings:
            svc = f.service.upper()
            if svc not in findings_by_service:
                findings_by_service[svc] = []
            findings_by_service[svc].append(f.to_dict())
        accounts = []
        for s in summaries:
            accounts.append({
                "name": s.account_name, "id": s.account_id, "region": s.region,
            })
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_findings": len(findings),
            "total_failed": len(failed),
            "total_passed": status_counts["pass"],
            "total_errors": status_counts["error"],
            "severity_counts": severity_counts,
            "service_counts": service_counts,
            "region_counts": self._build_region_counts(failed),
            "status_counts": status_counts,
            "accounts": accounts,
            "services_scanned": list(findings_by_service.keys()),
            "findings_by_service": findings_by_service,
            "findings": [f.to_dict() for f in findings],
        }

    def _build_region_counts(self, failed_findings: list[Finding]) -> dict:
        """Build region-level counts for the dashboard."""
        region_counts = {}
        for f in failed_findings:
            region = (f.region or "GLOBAL").upper()
            if region not in region_counts:
                region_counts[region] = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
            region_counts[region]["total"] += 1
            sev = f.severity.value if f.severity else "medium"
            if sev in region_counts[region]:
                region_counts[region][sev] += 1
        return region_counts

    def _render_html(self, data: dict) -> str:
        """Render the complete HTML dashboard."""
        findings_json = json.dumps(data, ensure_ascii=False)
        css = self._get_css()
        body = self._get_html_body()
        js = self._get_javascript()
        return (
            '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            '<title>Huawei Cloud Security Scanner | Dashboard</title>\n'
            '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>\n'
            '<style>\n' + css + '\n</style>\n'
            '</head>\n<body>\n'
            + body +
            '\n<script>\nconst SCAN_DATA = ' + findings_json + ';\n'
            + js +
            '\n</script>\n</body>\n</html>'
        )

    def _get_css(self) -> str:
        """Return all CSS styles for the AWS Service Screener-style dashboard."""
        return (
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
            "body { font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; background: #f4f4f4; color: #333; font-size: 14px; }\n"
            ".layout { display: flex; min-height: 100vh; }\n"
            "/* Sidebar */\n"
            ".sidebar { width: 220px; background: #232f3e; color: #fff; position: fixed; height: 100vh; overflow-y: auto; transition: transform 0.3s; z-index: 1000; border-right: 3px solid #f0ad4e; }\n"
            ".sidebar-header { padding: 15px 12px; background: #1a2332; border-bottom: 1px solid #37475a; text-align: center; }\n"
            ".logo { display: flex; align-items: center; gap: 8px; justify-content: center; }\n"
            ".logo-icon { width: 36px; height: 36px; background: #f0ad4e; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 18px; }\n"
            ".logo-text { font-size: 13px; font-weight: 700; color: #fff; line-height: 1.2; }\n"
            ".logo-subtitle { font-size: 10px; color: #f0ad4e; font-style: italic; }\n"
            ".nav-menu { list-style: none; padding: 5px 0; }\n"
            ".nav-section { padding: 12px 15px 4px; font-size: 10px; text-transform: uppercase; color: #8899a6; letter-spacing: 1.2px; font-weight: 600; }\n"
            ".nav-item { padding: 8px 15px; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: background 0.15s; font-size: 13px; color: #d5dbdb; }\n"
            ".nav-item:hover { background: #37475a; color: #fff; }\n"
            ".nav-item.active { background: #0073bb; color: #fff; font-weight: 600; }\n"
            ".nav-icon { font-size: 14px; width: 18px; text-align: center; }\n"
            "/* Main Content */\n"
            ".main-content { margin-left: 220px; flex: 1; min-height: 100vh; background: #f4f4f4; }\n"
            ".top-bar { display: flex; align-items: center; justify-content: space-between; padding: 10px 25px; background: #fff; border-bottom: 2px solid #e8e8e8; position: sticky; top: 0; z-index: 100; }\n"
            ".menu-toggle { display: none; background: none; border: none; font-size: 22px; cursor: pointer; color: #232f3e; }\n"
            ".top-bar-left { display: flex; align-items: center; gap: 15px; }\n"
            ".top-bar-link { color: #0073bb; font-size: 13px; text-decoration: none; }\n"
            ".breadcrumb { font-size: 13px; color: #666; }\n"
            ".account-selector select { padding: 5px 10px; border: 1px solid #ccc; border-radius: 3px; font-size: 12px; }\n"
            ".page { display: none; padding: 20px 25px; }\n"
            ".page.active { display: block; }\n"
            ".page-title { font-size: 22px; font-weight: 400; color: #232f3e; margin-bottom: 20px; }\n"
            + self._get_css_cards()
            + self._get_css_tables()
        )

    def _get_css_cards(self) -> str:
        """CSS for stat cards, section panels, charts, check cards."""
        return (
            "/* KPI Stat Cards */\n"
            ".stat-cards-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0; margin-bottom: 20px; }\n"
            ".stat-card { padding: 15px 18px; color: #fff; position: relative; min-height: 90px; display: flex; flex-direction: column; justify-content: center; }\n"
            ".stat-card-number { font-size: 36px; font-weight: 700; line-height: 1; }\n"
            ".stat-card-label { font-size: 12px; margin-top: 4px; opacity: 0.9; }\n"
            ".stat-card-icon { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); font-size: 40px; opacity: 0.3; }\n"
            ".stat-card.green { background: #27ae60; }\n"
            ".stat-card.blue { background: #2980b9; }\n"
            ".stat-card.teal { background: #1abc9c; }\n"
            ".stat-card.yellow { background: #f0ad4e; }\n"
            ".stat-card.red { background: #e74c3c; }\n"
            ".stat-card.navy { background: #232f3e; }\n"
            "/* Section Panels */\n"
            ".section-panel { background: #fff; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n"
            ".section-header { background: #f0ad4e; color: #fff; padding: 10px 18px; font-size: 14px; font-weight: 600; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }\n"
            ".section-header .toggle-icon { font-size: 18px; font-weight: bold; }\n"
            ".section-header.teal-header { background: #1abc9c; }\n"
            ".section-header.red-header { background: #e74c3c; }\n"
            ".section-body { padding: 18px; display: block; }\n"
            ".section-body.collapsed { display: none; }\n"
            "/* Charts */\n"
            ".charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 20px; }\n"
            ".chart-panel { background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n"
            ".chart-panel canvas { padding: 15px; }\n"
            "/* Check Cards */\n"
            ".check-cards-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; }\n"
            ".check-card { background: #fff; border: 1px solid #e8e8e8; padding: 12px 15px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; transition: box-shadow 0.15s; }\n"
            ".check-card:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.12); }\n"
            ".check-card-name { font-size: 13px; color: #232f3e; font-weight: 500; }\n"
            ".check-card-badges { display: flex; gap: 4px; align-items: center; }\n"
            ".pillar-badge { padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 600; color: #fff; }\n"
            ".pillar-security { background: #e74c3c; }\n"
            ".pillar-reliability { background: #3498db; }\n"
            ".pillar-performance { background: #9b59b6; }\n"
            ".pillar-cost { background: #f39c12; }\n"
            ".pillar-operational { background: #1abc9c; }\n"
            ".severity-dot { width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 10px; color: #fff; font-weight: bold; }\n"
            ".dot-critical,.dot-high { background: #e74c3c; }\n"
            ".dot-medium { background: #f0ad4e; }\n"
            ".dot-low { background: #5bc0de; }\n"
            ".dot-info { background: #5cb85c; }\n"
        )

    def _get_css_tables(self) -> str:
        """CSS for tables, badges, filters, detail cards, responsive."""
        return (
            "/* Table toolbar */\n"
            ".table-toolbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; flex-wrap: wrap; gap: 8px; }\n"
            ".table-toolbar-left { display: flex; gap: 5px; align-items: center; }\n"
            ".table-toolbar-left button { padding: 5px 12px; border: 1px solid #ccc; background: #f8f8f8; font-size: 12px; cursor: pointer; border-radius: 3px; }\n"
            ".table-toolbar-left button:hover { background: #e8e8e8; }\n"
            ".table-toolbar-right { display: flex; align-items: center; gap: 5px; }\n"
            ".table-toolbar-right label { font-size: 13px; color: #666; }\n"
            ".table-toolbar-right input { padding: 5px 10px; border: 1px solid #ccc; border-radius: 3px; font-size: 13px; width: 180px; }\n"
            ".show-entries { display: flex; align-items: center; gap: 5px; font-size: 13px; }\n"
            ".show-entries select { padding: 3px 8px; border: 1px solid #ccc; border-radius: 3px; }\n"
            "/* Findings Table */\n"
            ".findings-table { width: 100%; border-collapse: collapse; background: #fff; font-size: 13px; }\n"
            ".findings-table th { background: #fff; color: #232f3e; padding: 10px 12px; text-align: left; border-bottom: 2px solid #dee2e6; font-weight: 600; cursor: pointer; white-space: nowrap; }\n"
            ".findings-table th:hover { color: #0073bb; }\n"
            ".findings-table td { padding: 9px 12px; border-bottom: 1px solid #eee; vertical-align: top; }\n"
            ".findings-table tr:hover { background: #f8f9fa; }\n"
            "/* Tabs */\n"
            ".tabs { display: flex; margin-bottom: 15px; border-bottom: 2px solid #dee2e6; }\n"
            ".tab-btn { padding: 8px 20px; font-size: 14px; cursor: pointer; border: none; background: none; color: #0073bb; border-bottom: 3px solid transparent; margin-bottom: -2px; }\n"
            ".tab-btn.active { border-bottom-color: #0073bb; font-weight: 600; }\n"
            "/* Badges */\n"
            ".badge { padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }\n"
            ".badge-fail,.badge-high { background: #e74c3c; color: #fff; }\n"
            ".badge-pass { background: #27ae60; color: #fff; }\n"
            ".badge-error { background: #f0ad4e; color: #fff; }\n"
            ".badge-critical { background: #8e44ad; color: #fff; }\n"
            ".badge-medium { background: #f0ad4e; color: #fff; }\n"
            ".badge-low { background: #5bc0de; color: #fff; }\n"
            ".badge-informational,.badge-info { background: #5cb85c; color: #fff; }\n"
            ".badge-new { background: #d4edda; color: #155724; }\n"
            "/* Filter */\n"
            ".filter-panel { margin-bottom: 15px; }\n"
            ".filter-group { display: flex; flex-direction: column; gap: 4px; }\n"
            ".filter-group label { font-size: 12px; font-weight: 600; color: #555; }\n"
            ".filter-group select,.filter-group input { padding: 6px 10px; border: 1px solid #ccc; border-radius: 3px; font-size: 13px; min-width: 160px; }\n"
            "/* Resource Detail Cards */\n"
            ".region-label { font-size: 14px; font-weight: 600; color: #232f3e; margin: 15px 0 8px; }\n"
            ".resource-card { background: #fff; border: 1px solid #e8e8e8; margin-bottom: 10px; }\n"
            ".resource-card-header { background: #f0ad4e; color: #fff; padding: 8px 15px; font-size: 13px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; }\n"
            ".resource-card-header .svc-badge { background: #27ae60; padding: 2px 8px; border-radius: 3px; font-size: 11px; }\n"
            ".resource-table { width: 100%; border-collapse: collapse; }\n"
            ".resource-table th { background: #f8f8f8; padding: 6px 12px; text-align: left; font-size: 12px; color: #666; border-bottom: 1px solid #eee; }\n"
            ".resource-table td { padding: 6px 12px; font-size: 12px; border-bottom: 1px solid #f0f0f0; }\n"
            ".check-icon { margin-right: 4px; }\n"
            ".check-pass { color: #27ae60; }\n"
            ".check-fail { color: #e74c3c; }\n"
            ".check-warn { color: #f0ad4e; }\n"
            "/* Responsive */\n"
            "@media (max-width: 900px) { .sidebar { transform: translateX(-100%); } .sidebar.open { transform: translateX(0); } .main-content { margin-left: 0; } .menu-toggle { display: block; } .stat-cards-row { grid-template-columns: repeat(2, 1fr); } .charts-row { grid-template-columns: 1fr; } .check-cards-grid { grid-template-columns: 1fr; } }\n"
        )

    def _get_html_body(self) -> str:
        """Return the HTML body structure."""
        parts = []
        parts.append('<div class="layout">')
        # Sidebar
        parts.append('<nav class="sidebar" id="sidebar">')
        parts.append('<div class="sidebar-header"><div class="logo">')
        parts.append('<div class="logo-icon">&#x1F6E1;</div>')
        parts.append('<div><div class="logo-text">HWCloud Scanner</div>')
        parts.append('<div class="logo-subtitle">Security Assessment</div></div>')
        parts.append('</div></div>')
        parts.append('<ul class="nav-menu">')
        parts.append('<li class="nav-section">Pages</li>')
        parts.append('<li class="nav-item active" data-page="home"><span class="nav-icon">&#x1F3E0;</span><span>Home</span></li>')
        parts.append('<li class="nav-item" data-page="findings"><span class="nav-icon">&#x1F4CB;</span><span>FINDINGS</span></li>')
        parts.append('</ul>')
        parts.append('<ul class="nav-menu" id="services-nav"><li class="nav-section">Services</li></ul>')
        parts.append('</nav>')
        # Main content
        parts.append('<main class="main-content">')
        # Top bar
        parts.append('<header class="top-bar">')
        parts.append('<div class="top-bar-left"><button class="menu-toggle" onclick="toggleSidebar()">&#9776;</button>')
        parts.append('<a class="top-bar-link" href="#">Visit GitHub</a></div>')
        parts.append('<span class="breadcrumb" id="breadcrumb">Home / INDEX</span>')
        parts.append('<div class="account-selector"><span>Account: </span>')
        parts.append('<select id="account-filter" onchange="filterByAccount()"><option value="all">All Accounts</option></select></div>')
        parts.append('</header>')
        # Home page
        parts.append(self._get_home_page_html())
        # Findings page
        parts.append(self._get_findings_page_html())
        # Service detail page
        parts.append(self._get_service_detail_page_html())
        parts.append('</main></div>')
        return '\n'.join(parts)

    def _get_home_page_html(self) -> str:
        """Home page HTML."""
        return (
            '<div class="page active" id="page-home">'
            '<h1 class="page-title">INDEX</h1>'
            '<div class="stat-cards-row" id="home-stat-cards"></div>'
            '<div class="section-panel">'
            '<div class="section-header" onclick="toggleSection(this)">Summary <span class="toggle-icon">+</span></div>'
            '<div class="section-body collapsed" id="home-summary-body"><div id="severity-summary-content"></div></div>'
            '</div>'
            '<div class="charts-row">'
            '<div class="chart-panel">'
            '<div class="section-header" onclick="toggleSection(this)">High Risk - Group by Service <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body"><canvas id="serviceChart" height="200"></canvas></div>'
            '</div>'
            '<div class="chart-panel">'
            '<div class="section-header" onclick="toggleSection(this)">High Risk - Group by Severity <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body"><canvas id="severityChart" height="200"></canvas></div>'
            '</div></div>'
            '<div class="section-panel">'
            '<div class="section-header teal-header" onclick="toggleSection(this)">Services Overview <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body"><div class="check-cards-grid" id="home-service-cards"></div></div>'
            '</div>'
            '<div class="section-panel">'
            '<div class="section-header" onclick="toggleSection(this)">&#x1F30D; Regions Overview <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body"><div class="check-cards-grid" id="home-region-cards"></div></div>'
            '</div></div>'
        )

    def _get_findings_page_html(self) -> str:
        """Findings page HTML."""
        return (
            '<div class="page" id="page-findings">'
            '<h1 class="page-title">FINDINGS</h1>'
            '<div class="tabs">'
            '<button class="tab-btn active" onclick="switchTab(\'findings-tab\')">Findings</button>'
            '<button class="tab-btn" onclick="switchTab(\'suppressed-tab\')">Suppressed</button>'
            '</div>'
            '<div id="findings-tab">'
            '<div class="table-toolbar">'
            '<div class="table-toolbar-left">'
            '<div class="show-entries">Show <select id="entries-count" onchange="changePageSize()">'
            '<option>25</option><option>50</option><option>100</option></select> entries</div>'
            '<button onclick="copyFindings()">Copy</button>'
            '<button onclick="exportCSV()">CSV</button>'
            '</div>'
            '<div class="table-toolbar-right">'
            '<label>Search:</label><input type="text" id="search-input" oninput="searchFindings()">'
            '</div></div>'
            '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px;">'
            '<div class="filter-group"><label>Service</label>'
            '<select id="filter-service" onchange="applyFilters()"><option value="all">All Services</option></select></div>'
            '<div class="filter-group"><label>Region</label>'
            '<select id="filter-region" onchange="applyFilters()"><option value="all">All Regions</option></select></div>'
            '<div class="filter-group"><label>Severity</label>'
            '<select id="filter-severity" onchange="applyFilters()">'
            '<option value="all">All</option><option value="critical">Critical</option>'
            '<option value="high">High</option><option value="medium">Medium</option>'
            '<option value="low">Low</option></select></div>'
            '<div class="filter-group"><label>Status</label>'
            '<select id="filter-status" onchange="applyFilters()">'
            '<option value="all">All</option><option value="fail">Fail</option>'
            '<option value="pass">Pass</option></select></div>'
            '</div>'
            '<table class="findings-table" id="findings-table"><thead><tr>'
            '<th onclick="sortTable(0)">Service &#x2195;</th>'
            '<th onclick="sortTable(1)">Region &#x2195;</th>'
            '<th onclick="sortTable(2)">Check &#x2195;</th>'
            '<th onclick="sortTable(3)">Type &#x2195;</th>'
            '<th onclick="sortTable(4)">ResourceID &#x2195;</th>'
            '<th onclick="sortTable(5)">Severity &#x2195;</th>'
            '<th onclick="sortTable(6)">Status &#x2195;</th>'
            '</tr></thead><tbody id="findings-tbody"></tbody></table>'
            '</div>'
            '<div id="suppressed-tab" style="display:none;"><p style="padding:20px;color:#666;">No suppressed findings.</p></div>'
            '</div>'
        )

    def _get_service_detail_page_html(self) -> str:
        """Service detail page HTML."""
        return (
            '<div class="page" id="page-service-detail">'
            '<h1 class="page-title" id="service-detail-title">SERVICE</h1>'
            '<div class="stat-cards-row" id="service-stat-cards"></div>'
            '<div class="section-panel">'
            '<div class="section-header" onclick="toggleSection(this)">Summary <span class="toggle-icon">+</span></div>'
            '<div class="section-body collapsed" id="svc-summary-body"></div></div>'
            '<div class="section-panel">'
            '<div class="section-header teal-header" onclick="toggleSection(this)">&#x1F50D; Filter <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body">'
            '<div class="filter-group"><label>Checks</label>'
            '<select id="svc-filter-check" onchange="applyServiceFilter()"><option value="all">Select checks...</option></select></div>'
            '<div style="display:flex;gap:15px;margin-top:10px;">'
            '<div class="filter-group"><label>Pillar</label>'
            '<select id="svc-filter-pillar" onchange="applyServiceFilter()"><option value="all">All</option></select></div>'
            '<div class="filter-group"><label>Criticality</label>'
            '<select id="svc-filter-criticality" onchange="applyServiceFilter()">'
            '<option value="all">All</option><option value="critical">Critical</option>'
            '<option value="high">High</option><option value="medium">Medium</option>'
            '<option value="low">Low</option></select></div>'
            '</div></div></div>'
            '<div class="check-cards-grid" id="svc-check-cards"></div>'
            '<div class="section-panel">'
            '<div class="section-header" onclick="toggleSection(this)">Detail <span class="toggle-icon">&minus;</span></div>'
            '<div class="section-body" id="svc-detail-body"></div></div>'
            '</div>'
        )

    def _get_javascript(self) -> str:
        """Return all JavaScript for dashboard interactivity."""
        return (
            'let currentSort = { col: -1, asc: true };\n'
            'let filteredFindings = [];\n'
            'document.addEventListener("DOMContentLoaded", function() { initDashboard(); });\n'
            'function initDashboard() {\n'
            '    renderHomeStatCards();\n'
            '    renderHomeSeveritySummary();\n'
            '    renderHomeServiceCards();\n'
            '    renderHomeRegionCards();\n'
            '    renderCharts();\n'
            '    filteredFindings = SCAN_DATA.findings;\n'
            '    renderFindingsTable(filteredFindings);\n'
            '    populateFilters();\n'
            '    populateServicesNav();\n'
            '    populateAccountFilter();\n'
            '}\n'
            + self._get_js_home()
            + self._get_js_charts()
            + self._get_js_findings()
            + self._get_js_navigation()
            + self._get_js_service_detail()
            + self._get_js_utilities()
        )

    def _get_js_home(self) -> str:
        """JS for home page rendering."""
        return (
            'function renderHomeStatCards() {\n'
            '    var container = document.getElementById("home-stat-cards");\n'
            '    var d = SCAN_DATA;\n'
            '    var cards = [\n'
            '        { num: d.services_scanned.length, label: "Services Scanned", cls: "green", icon: "&#x2699;" },\n'
            '        { num: d.total_findings, label: "Total Checks", cls: "blue", icon: "&#x1F50D;" },\n'
            '        { num: d.total_failed, label: "Failed Findings", cls: "red", icon: "&#x26A0;", onclick: "quickFilter(\\x27status\\x27, \\x27fail\\x27)" },\n'
            '        { num: d.total_passed, label: "Passed", cls: "teal", icon: "&#x2705;", onclick: "quickFilter(\\x27status\\x27, \\x27pass\\x27)" },\n'
            '        { num: d.severity_counts.critical + d.severity_counts.high, label: "Critical+High", cls: "navy", icon: "&#x1F6AB;", onclick: "quickFilterCriticalHigh()" },\n'
            '        { num: d.total_errors, label: "Errors", cls: "yellow", icon: "&#x26A1;" }\n'
            '    ];\n'
            '    container.innerHTML = cards.map(function(c) {\n'
            '        var clickAttr = c.onclick ? \' onclick="\' + c.onclick + \'" style="cursor:pointer"\' : "";\n'
            '        return \'<div class="stat-card \' + c.cls + \'"\' + clickAttr + \'>\' +\n'
            '            \'<div class="stat-card-number">\' + c.num + \'</div>\' +\n'
            '            \'<div class="stat-card-label">\' + c.label + \'</div>\' +\n'
            '            \'<div class="stat-card-icon">\' + c.icon + \'</div></div>\';\n'
            '    }).join("");\n'
            '}\n'
            'function renderHomeSeveritySummary() {\n'
            '    var el = document.getElementById("severity-summary-content");\n'
            '    var sc = SCAN_DATA.severity_counts;\n'
            '    var total = SCAN_DATA.total_failed || 1;\n'
            '    var items = [\n'
            '        { label: "Critical", count: sc.critical, color: "#8e44ad", filter: "critical" },\n'
            '        { label: "High", count: sc.high, color: "#e74c3c", filter: "high" },\n'
            '        { label: "Medium", count: sc.medium, color: "#f0ad4e", filter: "medium" },\n'
            '        { label: "Low", count: sc.low, color: "#5bc0de", filter: "low" },\n'
            '        { label: "Info", count: sc.informational, color: "#5cb85c", filter: "informational" }\n'
            '    ];\n'
            '    el.innerHTML = items.map(function(i) {\n'
            '        var pct = Math.round((i.count / total) * 100);\n'
            '        return \'<div style="display:flex;align-items:center;margin-bottom:8px;cursor:pointer;" onclick="quickFilter(\\x27severity\\x27, \\x27\' + i.filter + \'\\x27)">\' +\n'
            '            \'<span style="width:90px;font-weight:600;font-size:13px;">\' + i.label + \'</span>\' +\n'
            '            \'<div style="flex:1;height:22px;background:#ecf0f1;border-radius:3px;margin:0 10px;overflow:hidden;">\' +\n'
            '            \'<div style="width:\' + Math.max(pct,2) + \'%;height:100%;background:\' + i.color + \';border-radius:3px;display:flex;align-items:center;padding-left:6px;color:#fff;font-size:11px;font-weight:600;">\' + pct + \'%</div></div>\' +\n'
            '            \'<span style="font-weight:700;width:40px;text-align:right;">\' + i.count + \'</span></div>\';\n'
            '    }).join("");\n'
            '}\n'
            'function renderHomeServiceCards() {\n'
            '    var container = document.getElementById("home-service-cards");\n'
            '    var svcs = Object.keys(SCAN_DATA.service_counts);\n'
            '    container.innerHTML = svcs.map(function(svc) {\n'
            '        var count = SCAN_DATA.service_counts[svc];\n'
            '        return \'<div class="check-card" onclick="quickFilter(\\x27service\\x27, \\x27\' + svc.toLowerCase() + \'\\x27)">\' +\n'
            '            \'<span class="check-card-name">\' + svc + \'</span>\' +\n'
            '            \'<div class="check-card-badges">\' +\n'
            '            \'<span class="pillar-badge pillar-security">Security</span>\' +\n'
            '            \'<span class="severity-dot dot-high">\' + count + \'</span></div></div>\';\n'
            '    }).join("");\n'
            '}\n'
            'function renderHomeRegionCards() {\n'
            '    var container = document.getElementById("home-region-cards");\n'
            '    var regions = SCAN_DATA.region_counts || {};\n'
            '    var keys = Object.keys(regions);\n'
            '    if (keys.length === 0) { container.innerHTML = \'<p style="color:#999;">No region data available.</p>\'; return; }\n'
            '    container.innerHTML = keys.map(function(region) {\n'
            '        var rc = regions[region];\n'
            '        var critHigh = (rc.critical || 0) + (rc.high || 0);\n'
            '        var dotCls = critHigh > 0 ? "dot-high" : (rc.medium > 0 ? "dot-medium" : "dot-low");\n'
            '        return \'<div class="check-card" onclick="quickFilter(\\x27region\\x27, \\x27\' + region.toLowerCase() + \'\\x27)">\' +\n'
            '            \'<span class="check-card-name">&#x1F30D; \' + region + \'</span>\' +\n'
            '            \'<div class="check-card-badges">\' +\n'
            '            \'<span class="pillar-badge pillar-operational">\' + rc.total + \' findings</span>\' +\n'
            '            \'<span class="severity-dot \' + dotCls + \'">\' + critHigh + \'</span></div></div>\';\n'
            '    }).join("");\n'
            '}\n'
        )

    def _get_js_charts(self) -> str:
        """JS for Chart.js rendering."""
        return (
            'function renderCharts() {\n'
            '    var sevCtx = document.getElementById("severityChart").getContext("2d");\n'
            '    new Chart(sevCtx, {\n'
            '        type: "doughnut",\n'
            '        data: {\n'
            '            labels: ["Critical", "High", "Medium", "Low", "Info"],\n'
            '            datasets: [{ data: [\n'
            '                SCAN_DATA.severity_counts.critical, SCAN_DATA.severity_counts.high,\n'
            '                SCAN_DATA.severity_counts.medium, SCAN_DATA.severity_counts.low,\n'
            '                SCAN_DATA.severity_counts.informational\n'
            '            ], backgroundColor: ["#8e44ad","#e74c3c","#f0ad4e","#5bc0de","#5cb85c"] }]\n'
            '        },\n'
            '        options: { responsive: true, plugins: { legend: { position: "right" } } }\n'
            '    });\n'
            '    var svcCtx = document.getElementById("serviceChart").getContext("2d");\n'
            '    var services = Object.keys(SCAN_DATA.service_counts);\n'
            '    var svcData = services.map(function(s) { return SCAN_DATA.service_counts[s]; });\n'
            '    var colors = ["#e74c3c","#f0ad4e","#5bc0de","#5cb85c","#8e44ad","#232f3e"];\n'
            '    var barColors = services.map(function(_, i) { return colors[i % 6]; });\n'
            '    new Chart(svcCtx, {\n'
            '        type: "bar",\n'
            '        data: { labels: services, datasets: [{ label: "Findings", data: svcData, backgroundColor: barColors }] },\n'
            '        options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }\n'
            '    });\n'
            '}\n'
        )

    def _get_js_findings(self) -> str:
        """JS for findings table, filters, search, sort."""
        return (
            'function renderFindingsTable(findings) {\n'
            '    var tbody = document.getElementById("findings-tbody");\n'
            '    if (!findings || findings.length === 0) { tbody.innerHTML = \'<tr><td colspan="7" style="text-align:center;padding:20px;color:#999;">No findings</td></tr>\'; return; }\n'
            '    tbody.innerHTML = findings.map(function(f) {\n'
            '        var sev = f.severity || "medium";\n'
            '        return \'<tr>\' +\n'
            '            \'<td>\' + (f.service || "").toUpperCase() + \'</td>\' +\n'
            '            \'<td>\' + (f.region || "GLOBAL") + \'</td>\' +\n'
            '            \'<td>\' + (f.check_id || f.description || "-") + \'</td>\' +\n'
            '            \'<td>Security</td>\' +\n'
            '            \'<td>\' + (f.resource_name || f.resource_id || "-") + \'</td>\' +\n'
            '            \'<td><span class="badge badge-\' + sev + \'">\' + sev.charAt(0).toUpperCase() + sev.slice(1) + \'</span></td>\' +\n'
            '            \'<td><span class="badge badge-\' + (f.status || "fail") + \'">\' + (f.status || "fail").charAt(0).toUpperCase() + (f.status || "fail").slice(1) + \'</span></td></tr>\';\n'
            '    }).join("");\n'
            '}\n'
            'function populateFilters() {\n'
            '    var sf = document.getElementById("filter-service");\n'
            '    SCAN_DATA.services_scanned.forEach(function(s) {\n'
            '        var opt = document.createElement("option"); opt.value = s.toLowerCase(); opt.textContent = s; sf.appendChild(opt);\n'
            '    });\n'
            '    // Populate region filter\n'
            '    var rf = document.getElementById("filter-region");\n'
            '    var regions = [];\n'
            '    SCAN_DATA.findings.forEach(function(f) {\n'
            '        var r = (f.region || "GLOBAL").toLowerCase();\n'
            '        if (regions.indexOf(r) === -1) regions.push(r);\n'
            '    });\n'
            '    regions.sort();\n'
            '    regions.forEach(function(r) {\n'
            '        var opt = document.createElement("option"); opt.value = r; opt.textContent = r.toUpperCase(); rf.appendChild(opt);\n'
            '    });\n'
            '}\n'
            'function populateServicesNav() {\n'
            '    var nav = document.getElementById("services-nav");\n'
            '    SCAN_DATA.services_scanned.forEach(function(s) {\n'
            '        var li = document.createElement("li"); li.className = "nav-item";\n'
            '        li.setAttribute("data-page", "service-" + s.toLowerCase());\n'
            '        li.innerHTML = \'<span class="nav-icon">&#x2699;</span><span>\' + s + \'</span>\';\n'
            '        li.onclick = function() { showServiceDetail(s); };\n'
            '        nav.appendChild(li);\n'
            '    });\n'
            '}\n'
            'function populateAccountFilter() {\n'
            '    var sel = document.getElementById("account-filter");\n'
            '    SCAN_DATA.accounts.forEach(function(a) {\n'
            '        var opt = document.createElement("option"); opt.value = a.id || a.name;\n'
            '        opt.textContent = (a.name || "") + " (" + (a.id || "N/A") + ")"; sel.appendChild(opt);\n'
            '    });\n'
            '}\n'
            'function applyFilters() {\n'
            '    var severity = document.getElementById("filter-severity").value;\n'
            '    var status = document.getElementById("filter-status").value;\n'
            '    var service = document.getElementById("filter-service").value;\n'
            '    var region = document.getElementById("filter-region").value;\n'
            '    var filtered = SCAN_DATA.findings;\n'
            '    if (severity !== "all") filtered = filtered.filter(function(f) { return f.severity === severity; });\n'
            '    if (status !== "all") filtered = filtered.filter(function(f) { return f.status === status; });\n'
            '    if (service !== "all") filtered = filtered.filter(function(f) { return (f.service || "").toLowerCase() === service; });\n'
            '    if (region !== "all") filtered = filtered.filter(function(f) { return (f.region || "GLOBAL").toLowerCase() === region; });\n'
            '    filteredFindings = filtered;\n'
            '    renderFindingsTable(filtered);\n'
            '}\n'
            'function quickFilter(filterType, value) {\n'
            '    // Navigate to Findings page with a pre-set filter\n'
            '    showPage("findings");\n'
            '    // Reset all filters first\n'
            '    document.getElementById("filter-service").value = "all";\n'
            '    document.getElementById("filter-region").value = "all";\n'
            '    document.getElementById("filter-severity").value = "all";\n'
            '    document.getElementById("filter-status").value = "all";\n'
            '    document.getElementById("search-input").value = "";\n'
            '    // Set the requested filter\n'
            '    if (filterType === "service") document.getElementById("filter-service").value = value;\n'
            '    else if (filterType === "region") document.getElementById("filter-region").value = value;\n'
            '    else if (filterType === "severity") document.getElementById("filter-severity").value = value;\n'
            '    else if (filterType === "status") document.getElementById("filter-status").value = value;\n'
            '    applyFilters();\n'
            '}\n'
            'function quickFilterCriticalHigh() {\n'
            '    showPage("findings");\n'
            '    document.getElementById("filter-service").value = "all";\n'
            '    document.getElementById("filter-region").value = "all";\n'
            '    document.getElementById("filter-severity").value = "all";\n'
            '    document.getElementById("filter-status").value = "all";\n'
            '    document.getElementById("search-input").value = "";\n'
            '    // Custom filter for critical + high\n'
            '    filteredFindings = SCAN_DATA.findings.filter(function(f) {\n'
            '        return f.severity === "critical" || f.severity === "high";\n'
            '    });\n'
            '    renderFindingsTable(filteredFindings);\n'
            '}\n'
            'function searchFindings() {\n'
            '    var q = document.getElementById("search-input").value.toLowerCase();\n'
            '    if (!q) { applyFilters(); return; }\n'
            '    var r = filteredFindings.filter(function(f) {\n'
            '        return (f.service||"").toLowerCase().includes(q) || (f.check_id||"").toLowerCase().includes(q) ||\n'
            '            (f.description||"").toLowerCase().includes(q) || (f.resource_id||"").toLowerCase().includes(q) ||\n'
            '            (f.region||"").toLowerCase().includes(q);\n'
            '    });\n'
            '    renderFindingsTable(r);\n'
            '}\n'
            'function filterByAccount() {\n'
            '    var val = document.getElementById("account-filter").value;\n'
            '    if (val === "all") { filteredFindings = SCAN_DATA.findings; }\n'
            '    else { filteredFindings = SCAN_DATA.findings.filter(function(f) { return f.account_id === val || f.account_name === val; }); }\n'
            '    renderFindingsTable(filteredFindings);\n'
            '}\n'
            'function sortTable(colIdx) {\n'
            '    if (currentSort.col === colIdx) currentSort.asc = !currentSort.asc;\n'
            '    else { currentSort.col = colIdx; currentSort.asc = true; }\n'
            '    var keys = ["service","region","check_id","type","resource_id","severity","status"];\n'
            '    var key = keys[colIdx] || "service";\n'
            '    filteredFindings.sort(function(a, b) {\n'
            '        var va = (a[key] || "").toLowerCase(), vb = (b[key] || "").toLowerCase();\n'
            '        return currentSort.asc ? va.localeCompare(vb) : vb.localeCompare(va);\n'
            '    });\n'
            '    renderFindingsTable(filteredFindings);\n'
            '}\n'
        )

    def _get_js_navigation(self) -> str:
        """JS for page navigation and UI toggles."""
        return (
            'function showPage(pageId) {\n'
            '    document.querySelectorAll(".page").forEach(function(p) { p.classList.remove("active"); });\n'
            '    document.querySelectorAll(".nav-item").forEach(function(n) { n.classList.remove("active"); });\n'
            '    var page = document.getElementById("page-" + pageId);\n'
            '    if (page) page.classList.add("active");\n'
            '    var navItem = document.querySelector(\'[data-page="\' + pageId + \'"]\');\n'
            '    if (navItem) navItem.classList.add("active");\n'
            '    document.getElementById("breadcrumb").textContent = "Home / " + pageId.toUpperCase();\n'
            '}\n'
            'document.querySelectorAll(".nav-item[data-page]").forEach(function(item) {\n'
            '    item.addEventListener("click", function() { showPage(item.dataset.page); });\n'
            '});\n'
            'function toggleSidebar() { document.getElementById("sidebar").classList.toggle("open"); }\n'
            'function toggleSection(header) {\n'
            '    var body = header.nextElementSibling;\n'
            '    var icon = header.querySelector(".toggle-icon");\n'
            '    if (body.classList.contains("collapsed") || body.style.display === "none") {\n'
            '        body.classList.remove("collapsed"); body.style.display = "block"; icon.innerHTML = "\\u2212";\n'
            '    } else {\n'
            '        body.classList.add("collapsed"); body.style.display = "none"; icon.innerHTML = "+";\n'
            '    }\n'
            '}\n'
            'function switchTab(tabId) {\n'
            '    document.querySelectorAll(".tab-btn").forEach(function(b) { b.classList.remove("active"); });\n'
            '    event.target.classList.add("active");\n'
            '    document.getElementById("findings-tab").style.display = tabId === "findings-tab" ? "block" : "none";\n'
            '    document.getElementById("suppressed-tab").style.display = tabId === "suppressed-tab" ? "block" : "none";\n'
            '}\n'
        )

    def _get_js_service_detail(self) -> str:
        """JS for service detail page."""
        return (
            'function showServiceDetail(service) {\n'
            '    showPage("service-detail");\n'
            '    document.getElementById("service-detail-title").textContent = service;\n'
            '    document.getElementById("breadcrumb").textContent = "Home / " + service;\n'
            '    var findings = SCAN_DATA.findings_by_service[service] || [];\n'
            '    var failed = findings.filter(function(f) { return f.status === "fail"; });\n'
            '    var uniqueChecks = [];\n'
            '    findings.forEach(function(f) { if (uniqueChecks.indexOf(f.check_id) === -1 && f.check_id) uniqueChecks.push(f.check_id); });\n'
            '    // Stat cards\n'
            '    var sc = document.getElementById("service-stat-cards");\n'
            '    var stats = [\n'
            '        { num: findings.length, label: "Resources", cls: "green", icon: "&#x1F4E6;" },\n'
            '        { num: failed.length, label: "Total Findings", cls: "blue", icon: "&#x1F50D;" },\n'
            '        { num: findings.length, label: "Rules Executed", cls: "teal", icon: "&#x2699;" },\n'
            '        { num: uniqueChecks.length, label: "Unique Rules", cls: "yellow", icon: "&#x2714;" },\n'
            '        { num: 0, label: "Suppressed", cls: "red", icon: "&#x1F6AB;" }\n'
            '    ];\n'
            '    sc.innerHTML = stats.map(function(c) {\n'
            '        return \'<div class="stat-card \' + c.cls + \'"><div class="stat-card-number">\' + c.num + \'</div>\' +\n'
            '            \'<div class="stat-card-label">\' + c.label + \'</div><div class="stat-card-icon">\' + c.icon + \'</div></div>\';\n'
            '    }).join("");\n'
            '    // Check cards\n'
            '    var cc = document.getElementById("svc-check-cards");\n'
            '    cc.innerHTML = uniqueChecks.map(function(chk) {\n'
            '        var chkF = failed.filter(function(f) { return f.check_id === chk; });\n'
            '        var sev = chkF.length > 0 ? (chkF[0].severity || "medium") : "low";\n'
            '        var dotCls = (sev === "critical" || sev === "high") ? "dot-high" : sev === "medium" ? "dot-medium" : "dot-low";\n'
            '        return \'<div class="check-card"><span class="check-card-name">\' + chk + \'</span>\' +\n'
            '            \'<div class="check-card-badges"><span class="pillar-badge pillar-security">Security</span>\' +\n'
            '            \'<span class="severity-dot \' + dotCls + \'">&#x26A0;</span></div></div>\';\n'
            '    }).join("");\n'
            '    // Detail - resource level\n'
            '    var detailBody = document.getElementById("svc-detail-body");\n'
            '    var byRegion = {};\n'
            '    findings.forEach(function(f) { var r = f.region || "GLOBAL"; if (!byRegion[r]) byRegion[r] = []; byRegion[r].push(f); });\n'
            '    var html = "";\n'
            '    Object.keys(byRegion).forEach(function(region) {\n'
            '        html += \'<div class="region-label">\' + region + \'</div>\';\n'
            '        var byRes = {};\n'
            '        byRegion[region].forEach(function(f) { var rid = f.resource_name || f.resource_id || "Unknown"; if (!byRes[rid]) byRes[rid] = []; byRes[rid].push(f); });\n'
            '        var idx = 1;\n'
            '        Object.keys(byRes).forEach(function(rid) {\n'
            '            var resF = byRes[rid];\n'
            '            html += \'<div class="resource-card"><div class="resource-card-header"><span>\' + idx + \'. \' + rid + \'</span>\' +\n'
            '                \'<span class="svc-badge">\' + service + \'</span></div>\';\n'
            '            html += \'<table class="resource-table"><thead><tr><th>Check</th><th>Current Value</th><th>Recommendation</th></tr></thead><tbody>\';\n'
            '            resF.forEach(function(f) {\n'
            '                var icon = f.status === "fail" ? \'<span class="check-icon check-fail">&#x2718;</span>\' :\n'
            '                    f.status === "pass" ? \'<span class="check-icon check-pass">&#x2714;</span>\' :\n'
            '                    \'<span class="check-icon check-warn">&#x26A0;</span>\';\n'
            '                html += \'<tr><td>\' + icon + " " + (f.check_id || "-") + \'</td><td>\' + (f.description || "-") + \'</td><td>\' + (f.remediation || "-") + \'</td></tr>\';\n'
            '            });\n'
            '            html += \'</tbody></table></div>\';\n'
            '            idx++;\n'
            '        });\n'
            '    });\n'
            '    detailBody.innerHTML = html || \'<p style="color:#999;">No detail data.</p>\';\n'
            '    // Populate check filter\n'
            '    var cf = document.getElementById("svc-filter-check");\n'
            '    cf.innerHTML = \'<option value="all">Select checks...</option>\';\n'
            '    uniqueChecks.forEach(function(c) { var o = document.createElement("option"); o.value = c; o.textContent = c; cf.appendChild(o); });\n'
            '}\n'
            'function applyServiceFilter() { /* placeholder */ }\n'
        )

    def _get_js_utilities(self) -> str:
        """JS utility functions (copy, export, etc.)."""
        return (
            'function copyFindings() {\n'
            '    var table = document.getElementById("findings-table");\n'
            '    var range = document.createRange(); range.selectNode(table);\n'
            '    window.getSelection().removeAllRanges(); window.getSelection().addRange(range);\n'
            '    document.execCommand("copy"); window.getSelection().removeAllRanges();\n'
            '    alert("Table copied to clipboard");\n'
            '}\n'
            'function exportCSV() {\n'
            '    var csv = "Service,Region,Check,Type,ResourceID,Severity,Status\\n";\n'
            '    filteredFindings.forEach(function(f) {\n'
            '        csv += [(f.service||"").toUpperCase(), f.region||"GLOBAL", f.check_id||"",\n'
            '            "Security", f.resource_name||f.resource_id||"", f.severity||"", f.status||""].join(",") + "\\n";\n'
            '    });\n'
            '    var blob = new Blob([csv], { type: "text/csv" });\n'
            '    var url = URL.createObjectURL(blob);\n'
            '    var a = document.createElement("a"); a.href = url; a.download = "findings.csv"; a.click();\n'
            '    URL.revokeObjectURL(url);\n'
            '}\n'
            'function changePageSize() { renderFindingsTable(filteredFindings); }\n'
        )
