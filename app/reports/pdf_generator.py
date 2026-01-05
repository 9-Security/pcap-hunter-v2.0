"""PDF Report Generation for PCAP Hunter."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path

from app.utils.logger import get_logger

logger = get_logger(__name__)

# Try to import weasyprint, but make it optional
try:
    from weasyprint import CSS, HTML

    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
    logger.warning("weasyprint not installed. PDF generation disabled.")

try:
    import markdown

    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
    logger.warning("markdown not installed. Using basic markdown conversion.")


@dataclass
class ReportConfig:
    """Configuration for PDF report generation."""

    title: str = "PCAP Analysis Report"
    analyst: str = ""
    organization: str = ""
    classification: str = "TLP:CLEAR"  # TLP marking
    include_charts: bool = True
    include_raw_data: bool = True
    include_yara: bool = True
    include_osint: bool = True
    language: str = "en"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "analyst": self.analyst,
            "organization": self.organization,
            "classification": self.classification,
            "include_charts": self.include_charts,
            "include_raw_data": self.include_raw_data,
            "include_yara": self.include_yara,
            "include_osint": self.include_osint,
            "language": self.language,
        }


@dataclass
class PDFReport:
    """Generated PDF report."""

    content: bytes
    filename: str
    page_count: int
    generated_at: datetime


class PDFReportGenerator:
    """Generates professional PDF reports from analysis data."""

    def __init__(self, config: ReportConfig | None = None):
        """Initialize report generator."""
        self.config = config or ReportConfig()
        self._templates_dir = Path(__file__).parent / "templates"

    @property
    def is_available(self) -> bool:
        """Check if PDF generation is available."""
        return WEASYPRINT_AVAILABLE

    @staticmethod
    def _escape(value: str | None) -> str:
        """Escape HTML special characters to prevent XSS."""
        if value is None:
            return "N/A"
        return html.escape(str(value))

    def generate(
        self,
        report_md: str,
        features: dict,
        osint: dict | None = None,
        yara_results: dict | None = None,
        dns_analysis: dict | None = None,
        tls_analysis: dict | None = None,
        case_info: dict | None = None,
    ) -> PDFReport | None:
        """
        Generate a complete PDF report.

        Args:
            report_md: LLM-generated markdown report.
            features: Extracted features dictionary.
            osint: OSINT enrichment results.
            yara_results: YARA scan results.
            dns_analysis: DNS analysis results.
            tls_analysis: TLS certificate analysis results.
            case_info: Optional case information.

        Returns:
            PDFReport object or None if generation fails.
        """
        if not self.is_available:
            logger.error("PDF generation not available (weasyprint not installed)")
            return None

        try:
            # Build HTML content
            html_content = self._build_html(
                report_md=report_md,
                features=features,
                osint=osint,
                yara_results=yara_results,
                dns_analysis=dns_analysis,
                tls_analysis=tls_analysis,
                case_info=case_info,
            )

            # Generate PDF with accurate page count
            html = HTML(string=html_content)
            css = CSS(string=self._get_styles())

            # Render to get accurate page count
            document = html.render(stylesheets=[css])
            pdf_buffer = BytesIO()
            document.write_pdf(pdf_buffer)
            pdf_content = pdf_buffer.getvalue()

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"pcap_analysis_{timestamp}.pdf"

            # Get actual page count from rendered document
            page_count = len(document.pages)

            return PDFReport(
                content=pdf_content,
                filename=filename,
                page_count=page_count,
                generated_at=datetime.now(),
            )

        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None

    def _build_html(
        self,
        report_md: str,
        features: dict,
        osint: dict | None,
        yara_results: dict | None,
        dns_analysis: dict | None,
        tls_analysis: dict | None,
        case_info: dict | None,
    ) -> str:
        """Build the complete HTML document."""
        sections = []

        # Cover page
        sections.append(self._render_cover_page(case_info))

        # Table of Contents
        sections.append(self._render_toc())

        # Executive Summary (from LLM report)
        sections.append(self._render_executive_summary(report_md))

        # Key Findings / IOC Summary
        sections.append(self._render_ioc_table(features, osint))

        # OSINT Results
        if self.config.include_osint and osint:
            sections.append(self._render_osint_section(osint))

        # DNS Analysis
        if dns_analysis and not dns_analysis.get("skipped"):
            sections.append(self._render_dns_section(dns_analysis))

        # TLS Analysis
        if tls_analysis and not tls_analysis.get("skipped"):
            sections.append(self._render_tls_section(tls_analysis))

        # YARA Results - show if available flag is set OR if there are actual results
        if self.config.include_yara and yara_results:
            has_results = yara_results.get("yara_available") or yara_results.get("scanned", 0) > 0
            if has_results:
                sections.append(self._render_yara_section(yara_results))

        # Flow Analysis
        if self.config.include_raw_data and features.get("flows"):
            sections.append(self._render_flow_section(features))

        # Appendix
        sections.append(self._render_appendix(features))

        # Build full HTML
        body = "\n".join(sections)
        return f"""<!DOCTYPE html>
<html lang="{self.config.language}">
<head>
    <meta charset="UTF-8">
    <title>{self.config.title}</title>
</head>
<body>
{body}
</body>
</html>"""

    def _render_cover_page(self, case_info: dict | None) -> str:
        """Render the cover page."""
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d %H:%M")

        case_section = ""
        if case_info:
            case_section = f"""
            <p class="case-info">Case: {self._escape(case_info.get("title"))}</p>
            <p class="case-id">ID: {self._escape(case_info.get("id"))}</p>
            """

        return f"""
<div class="cover-page">
    <div class="classification">{self._escape(self.config.classification)}</div>
    <h1 class="report-title">{self._escape(self.config.title)}</h1>
    {case_section}
    <div class="metadata">
        <p><strong>Generated:</strong> {date_str}</p>
        <p><strong>Analyst:</strong> {self._escape(self.config.analyst) or "Not specified"}</p>
        <p><strong>Organization:</strong> {self._escape(self.config.organization) or "Not specified"}</p>
    </div>
    <div class="classification-footer">{self._escape(self.config.classification)}</div>
</div>
<div class="page-break"></div>
"""

    def _render_toc(self) -> str:
        """Render table of contents."""
        return """
<div class="toc">
    <h2>Table of Contents</h2>
    <ol>
        <li><a href="#summary">Executive Summary</a></li>
        <li><a href="#iocs">Indicators of Compromise</a></li>
        <li><a href="#osint">OSINT Analysis</a></li>
        <li><a href="#dns">DNS Analysis</a></li>
        <li><a href="#tls">TLS Certificate Analysis</a></li>
        <li><a href="#yara">YARA Scan Results</a></li>
        <li><a href="#flows">Network Flow Analysis</a></li>
        <li><a href="#appendix">Appendix</a></li>
    </ol>
</div>
<div class="page-break"></div>
"""

    def _render_executive_summary(self, report_md: str) -> str:
        """Render executive summary from markdown report."""
        # Convert markdown to HTML
        html_content = self._markdown_to_html(report_md)

        return f"""
<section id="summary">
    <h2>1. Executive Summary</h2>
    <div class="summary-content">
        {html_content}
    </div>
</section>
<div class="page-break"></div>
"""

    def _render_ioc_table(self, features: dict, osint: dict | None) -> str:
        """Render IOC summary table."""
        artifacts = features.get("artifacts", {})

        # Build IOC rows
        rows = []

        # IPs
        for ip in artifacts.get("ips", [])[:20]:
            osint_info = ""
            if osint and ip in osint.get("ips", {}):
                ip_data = osint["ips"][ip]
                gn = ip_data.get("greynoise", {}).get("classification", "")
                if gn:
                    osint_info = f"GreyNoise: {self._escape(gn)}"
            rows.append(f"<tr><td>IP Address</td><td>{self._escape(ip)}</td><td>{osint_info}</td></tr>")

        # Domains
        for domain in artifacts.get("domains", [])[:20]:
            rows.append(f"<tr><td>Domain</td><td>{self._escape(domain)}</td><td></td></tr>")

        # Hashes
        for h in artifacts.get("hashes", [])[:10]:
            rows.append(f"<tr><td>Hash (SHA256)</td><td class='hash'>{self._escape(h)}</td><td></td></tr>")

        # JA3
        for ja3 in artifacts.get("ja3", [])[:10]:
            rows.append(f"<tr><td>JA3 Fingerprint</td><td class='hash'>{self._escape(ja3)}</td><td></td></tr>")

        table_rows = "\n".join(rows) if rows else "<tr><td colspan='3'>No IOCs extracted</td></tr>"

        return f"""
<section id="iocs">
    <h2>2. Indicators of Compromise</h2>
    <table class="ioc-table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Context</th>
            </tr>
        </thead>
        <tbody>
            {table_rows}
        </tbody>
    </table>
</section>
<div class="page-break"></div>
"""

    def _render_osint_section(self, osint: dict) -> str:
        """Render OSINT analysis section."""
        ip_rows = []
        for ip, data in list(osint.get("ips", {}).items())[:15]:
            gn = data.get("greynoise", {}).get("classification", "N/A")
            vt = data.get("vt", {}).get("data", {}).get("attributes", {}).get("reputation", "N/A")
            ptr = data.get("ptr", "N/A")
            ip_rows.append(
                f"<tr><td>{self._escape(ip)}</td><td>{self._escape(ptr)}</td>"
                f"<td>{self._escape(gn)}</td><td>{self._escape(str(vt))}</td></tr>"
            )

        ip_table = "\n".join(ip_rows) if ip_rows else "<tr><td colspan='4'>No IP data</td></tr>"

        domain_rows = []
        for domain, data in list(osint.get("domains", {}).items())[:15]:
            cats = data.get("vt", {}).get("data", {}).get("attributes", {}).get("categories", {})
            cat_str = ", ".join(list(cats.values())[:3]) if isinstance(cats, dict) else str(cats)[:50]
            domain_rows.append(f"<tr><td>{self._escape(domain)}</td><td>{self._escape(cat_str)}</td></tr>")

        domain_table = "\n".join(domain_rows) if domain_rows else "<tr><td colspan='2'>No domain data</td></tr>"

        return f"""
<section id="osint">
    <h2>3. OSINT Analysis</h2>

    <h3>IP Address Intelligence</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>IP</th>
                <th>PTR</th>
                <th>GreyNoise</th>
                <th>VT Rep</th>
            </tr>
        </thead>
        <tbody>
            {ip_table}
        </tbody>
    </table>

    <h3>Domain Intelligence</h3>
    <table class="data-table">
        <thead>
            <tr>
                <th>Domain</th>
                <th>Categories</th>
            </tr>
        </thead>
        <tbody>
            {domain_table}
        </tbody>
    </table>
</section>
<div class="page-break"></div>
"""

    def _render_dns_section(self, dns_analysis: dict) -> str:
        """Render DNS analysis section."""
        stats = f"""
        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-value">{dns_analysis.get("total_records", 0)}</span>
                <span class="stat-label">DNS Records</span>
            </div>
            <div class="stat-box">
                <span class="stat-value">{dns_analysis.get("unique_domains", 0)}</span>
                <span class="stat-label">Unique Domains</span>
            </div>
            <div class="stat-box">
                <span class="stat-value">{dns_analysis.get("unique_dns_servers", 0)}</span>
                <span class="stat-label">DNS Servers</span>
            </div>
        </div>
        """

        alerts = dns_analysis.get("alerts", {})
        alert_section = ""
        if alerts.get("dga_count") or alerts.get("tunneling_count") or alerts.get("fast_flux_count"):
            alert_items = []
            if alerts.get("dga_count"):
                dga_cnt = alerts["dga_count"]
                alert_items.append(f"<li class='alert-high'>DGA Detection: {dga_cnt} suspicious domains</li>")
            if alerts.get("tunneling_count"):
                alert_items.append(
                    f"<li class='alert-high'>DNS Tunneling: {alerts['tunneling_count']} potential tunneling</li>"
                )
            if alerts.get("fast_flux_count"):
                alert_items.append(f"<li class='alert-medium'>Fast Flux: {alerts['fast_flux_count']} domains</li>")
            alert_section = f"<ul class='alert-list'>{''.join(alert_items)}</ul>"

        # DGA detections table
        dga_rows = []
        for d in dns_analysis.get("dga_detections", [])[:10]:
            dga_rows.append(
                f"<tr><td>{self._escape(d.get('domain', ''))}</td>"
                f"<td>{d.get('score', 0):.2f}</td>"
                f"<td>{self._escape(d.get('reason', ''))}</td></tr>"
            )
        dga_table = (
            f"""
        <h3>DGA Detection Results</h3>
        <table class="data-table">
            <thead><tr><th>Domain</th><th>Score</th><th>Reason</th></tr></thead>
            <tbody>{"".join(dga_rows)}</tbody>
        </table>
        """
            if dga_rows
            else ""
        )

        return f"""
<section id="dns">
    <h2>4. DNS Analysis</h2>
    {stats}
    {alert_section}
    {dga_table}
</section>
<div class="page-break"></div>
"""

    def _render_tls_section(self, tls_analysis: dict) -> str:
        """Render TLS certificate analysis section."""
        stats = f"""
        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-value">{tls_analysis.get("total_certificates", 0)}</span>
                <span class="stat-label">Certificates</span>
            </div>
            <div class="stat-box">
                <span class="stat-value">{tls_analysis.get("self_signed", 0)}</span>
                <span class="stat-label">Self-Signed</span>
            </div>
            <div class="stat-box">
                <span class="stat-value">{tls_analysis.get("expired", 0)}</span>
                <span class="stat-label">Expired</span>
            </div>
        </div>
        """

        cert_rows = []
        for cert in tls_analysis.get("certificates", [])[:15]:
            risk_class = "risk-high" if cert.get("risk_score", 0) >= 0.5 else ""
            cert_rows.append(
                f"<tr class='{risk_class}'>"
                f"<td>{self._escape(cert.get('subject_cn', 'N/A'))}</td>"
                f"<td>{self._escape(cert.get('issuer_cn', 'N/A'))}</td>"
                f"<td>{self._escape(cert.get('not_after', 'N/A'))}</td>"
                f"<td>{'Yes' if cert.get('is_self_signed') else 'No'}</td>"
                f"<td>{cert.get('risk_score', 0):.2f}</td>"
                f"</tr>"
            )

        cert_table = (
            f"""
        <h3>Certificate Details</h3>
        <table class="data-table">
            <thead><tr><th>Subject CN</th><th>Issuer CN</th><th>Expires</th>
            <th>Self-Signed</th><th>Risk</th></tr></thead>
            <tbody>{"".join(cert_rows)}</tbody>
        </table>
        """
            if cert_rows
            else ""
        )

        return f"""
<section id="tls">
    <h2>5. TLS Certificate Analysis</h2>
    {stats}
    {cert_table}
</section>
<div class="page-break"></div>
"""

    def _render_yara_section(self, yara_results: dict) -> str:
        """Render YARA scan results section."""
        stats = f"""
        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-value">{yara_results.get("scanned", 0)}</span>
                <span class="stat-label">Files Scanned</span>
            </div>
            <div class="stat-box {"alert-box" if yara_results.get("matched", 0) > 0 else ""}">
                <span class="stat-value">{yara_results.get("matched", 0)}</span>
                <span class="stat-label">Matches Found</span>
            </div>
            <div class="stat-box">
                <span class="stat-value">{yara_results.get("rule_count", 0)}</span>
                <span class="stat-label">Rules Loaded</span>
            </div>
        </div>
        """

        by_severity = yara_results.get("by_severity", {})
        severity_section = f"""
        <div class="severity-breakdown">
            <span class="severity critical">Critical: {by_severity.get("critical", 0)}</span>
            <span class="severity high">High: {by_severity.get("high", 0)}</span>
            <span class="severity medium">Medium: {by_severity.get("medium", 0)}</span>
            <span class="severity low">Low: {by_severity.get("low", 0)}</span>
            <span class="severity clean">Clean: {by_severity.get("clean", 0)}</span>
        </div>
        """

        match_rows = []
        for r in yara_results.get("results", []):
            if r.get("has_matches"):
                for m in r.get("matches", []):
                    sev_class = f"severity-{self._escape(r.get('severity', 'low'))}"
                    file_name = self._escape(Path(r.get("file_path", "")).name)
                    rule_name = self._escape(m.get("rule_name", ""))
                    tags = self._escape(", ".join(m.get("rule_tags", [])))
                    severity = self._escape(r.get("severity", "unknown"))
                    match_rows.append(
                        f"<tr class='{sev_class}'>"
                        f"<td>{file_name}</td>"
                        f"<td>{rule_name}</td>"
                        f"<td>{tags}</td>"
                        f"<td>{severity}</td>"
                        f"</tr>"
                    )

        match_table = (
            f"""
        <h3>Matched Files</h3>
        <table class="data-table">
            <thead><tr><th>File</th><th>Rule</th><th>Tags</th><th>Severity</th></tr></thead>
            <tbody>{"".join(match_rows)}</tbody>
        </table>
        """
            if match_rows
            else "<p>No malicious content detected.</p>"
        )

        return f"""
<section id="yara">
    <h2>6. YARA Scan Results</h2>
    {stats}
    {severity_section}
    {match_table}
</section>
<div class="page-break"></div>
"""

    def _render_flow_section(self, features: dict) -> str:
        """Render network flow analysis section."""
        flows = features.get("flows", [])[:50]

        flow_rows = []
        for f in flows:
            flow_rows.append(
                f"<tr>"
                f"<td>{self._escape(f.get('src', 'N/A'))}</td>"
                f"<td>{self._escape(str(f.get('sport', 'N/A')))}</td>"
                f"<td>{self._escape(f.get('dst', 'N/A'))}</td>"
                f"<td>{self._escape(str(f.get('dport', 'N/A')))}</td>"
                f"<td>{self._escape(f.get('proto', 'N/A'))}</td>"
                f"<td>{f.get('count', 0)}</td>"
                f"</tr>"
            )

        return f"""
<section id="flows">
    <h2>7. Network Flow Analysis</h2>
    <p>Showing top {len(flows)} flows by packet count.</p>
    <table class="data-table flow-table">
        <thead>
            <tr>
                <th>Source</th>
                <th>SPort</th>
                <th>Destination</th>
                <th>DPort</th>
                <th>Protocol</th>
                <th>Packets</th>
            </tr>
        </thead>
        <tbody>
            {"".join(flow_rows)}
        </tbody>
    </table>
</section>
<div class="page-break"></div>
"""

    def _render_appendix(self, features: dict) -> str:
        """Render appendix with raw data."""
        artifacts = features.get("artifacts", {})

        return f"""
<section id="appendix">
    <h2>8. Appendix</h2>

    <h3>Analysis Statistics</h3>
    <ul>
        <li>Total Flows: {len(features.get("flows", []))}</li>
        <li>Unique IPs: {len(artifacts.get("ips", []))}</li>
        <li>Unique Domains: {len(artifacts.get("domains", []))}</li>
        <li>File Hashes: {len(artifacts.get("hashes", []))}</li>
        <li>JA3 Fingerprints: {len(artifacts.get("ja3", []))}</li>
    </ul>

    <h3>Report Generation</h3>
    <ul>
        <li>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</li>
        <li>Classification: {self._escape(self.config.classification)}</li>
        <li>Tool: PCAP Hunter</li>
    </ul>
</section>
"""

    def _markdown_to_html(self, md_text: str) -> str:
        """Convert markdown to HTML with basic sanitization."""
        if MARKDOWN_AVAILABLE:
            html_output = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
        else:
            html_output = self._basic_markdown_convert(md_text)

        # Sanitize potentially dangerous HTML tags (defense in depth)
        # Remove script, style, iframe, object, embed, form tags
        dangerous_tags = ["script", "style", "iframe", "object", "embed", "form", "input", "button"]
        for tag in dangerous_tags:
            html_output = re.sub(rf"<{tag}[^>]*>.*?</{tag}>", "", html_output, flags=re.IGNORECASE | re.DOTALL)
            html_output = re.sub(rf"<{tag}[^>]*/?>", "", html_output, flags=re.IGNORECASE)

        # Remove on* event handlers (onclick, onerror, etc.)
        html_output = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', "", html_output, flags=re.IGNORECASE)
        html_output = re.sub(r"\s+on\w+\s*=\s*[^\s>]+", "", html_output, flags=re.IGNORECASE)

        # Remove javascript: URLs
        html_output = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', html_output, flags=re.IGNORECASE)

        return html_output

    def _basic_markdown_convert(self, md_text: str) -> str:
        """Basic markdown to HTML conversion (fallback)."""
        html = md_text

        # Headers
        html = re.sub(r"^### (.+)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)
        html = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
        html = re.sub(r"^# (.+)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)

        # Bold and italic
        html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
        html = re.sub(r"\*(.+?)\*", r"<em>\1</em>", html)

        # Lists
        html = re.sub(r"^- (.+)$", r"<li>\1</li>", html, flags=re.MULTILINE)

        # Code blocks
        html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)

        # Paragraphs
        html = re.sub(r"\n\n", r"</p><p>", html)
        html = f"<p>{html}</p>"

        return html

    def _get_styles(self) -> str:
        """Get CSS styles for the PDF."""
        return """
@page {
    size: A4;
    margin: 2cm;
    @top-right {
        content: "PCAP Hunter Report";
        font-size: 9pt;
        color: #666;
    }
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9pt;
        color: #666;
    }
}

body {
    font-family: 'Helvetica', 'Arial', sans-serif;
    font-size: 10pt;
    line-height: 1.5;
    color: #333;
}

h1 { font-size: 24pt; color: #1a1a2e; margin-bottom: 0.5em; }
h2 { font-size: 16pt; color: #16213e; margin-top: 1.5em; border-bottom: 2px solid #0f3460; padding-bottom: 0.3em; }
h3 { font-size: 12pt; color: #1a1a2e; margin-top: 1em; }

.cover-page {
    text-align: center;
    padding-top: 3cm;
}

.cover-page .classification {
    font-size: 14pt;
    font-weight: bold;
    color: #e94560;
    border: 2px solid #e94560;
    display: inline-block;
    padding: 0.3em 1em;
    margin-bottom: 2cm;
}

.cover-page .report-title {
    font-size: 32pt;
    margin-bottom: 1cm;
}

.cover-page .metadata {
    margin-top: 3cm;
    font-size: 11pt;
}

.cover-page .classification-footer {
    position: absolute;
    bottom: 2cm;
    left: 0;
    right: 0;
    text-align: center;
    font-size: 12pt;
    font-weight: bold;
    color: #e94560;
}

.page-break {
    page-break-after: always;
}

.toc {
    margin-top: 2cm;
}

.toc ol {
    list-style-type: decimal;
    padding-left: 1.5em;
}

.toc li {
    margin-bottom: 0.5em;
}

.toc a {
    color: #0f3460;
    text-decoration: none;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 9pt;
}

th, td {
    border: 1px solid #ddd;
    padding: 0.5em;
    text-align: left;
}

th {
    background-color: #0f3460;
    color: white;
    font-weight: bold;
}

tr:nth-child(even) {
    background-color: #f9f9f9;
}

.ioc-table td.hash {
    font-family: 'Courier New', monospace;
    font-size: 8pt;
    word-break: break-all;
}

.stats-grid {
    display: flex;
    justify-content: space-around;
    margin: 1em 0;
}

.stat-box {
    text-align: center;
    padding: 1em;
    border: 1px solid #ddd;
    border-radius: 5px;
    min-width: 100px;
}

.stat-box.alert-box {
    border-color: #e94560;
    background-color: #fff5f5;
}

.stat-value {
    display: block;
    font-size: 24pt;
    font-weight: bold;
    color: #0f3460;
}

.stat-label {
    display: block;
    font-size: 9pt;
    color: #666;
}

.alert-list {
    list-style: none;
    padding: 0;
}

.alert-list li {
    padding: 0.5em 1em;
    margin: 0.3em 0;
    border-radius: 3px;
}

.alert-high {
    background-color: #ffebee;
    border-left: 4px solid #e94560;
}

.alert-medium {
    background-color: #fff8e1;
    border-left: 4px solid #ff9800;
}

.risk-high {
    background-color: #ffebee;
}

.severity-breakdown {
    margin: 1em 0;
    display: flex;
    gap: 1em;
    flex-wrap: wrap;
}

.severity {
    padding: 0.3em 0.8em;
    border-radius: 3px;
    font-size: 9pt;
}

.severity.critical { background-color: #d32f2f; color: white; }
.severity.high { background-color: #f57c00; color: white; }
.severity.medium { background-color: #fbc02d; color: black; }
.severity.low { background-color: #7cb342; color: white; }
.severity.clean { background-color: #4caf50; color: white; }

.severity-critical { background-color: #ffebee; }
.severity-high { background-color: #fff3e0; }
.severity-medium { background-color: #fffde7; }

code {
    font-family: 'Courier New', monospace;
    background-color: #f5f5f5;
    padding: 0.1em 0.3em;
    border-radius: 2px;
}

.summary-content {
    background-color: #f9f9f9;
    padding: 1em;
    border-radius: 5px;
}
"""


def generate_pdf_report(
    report_md: str,
    features: dict,
    osint: dict | None = None,
    yara_results: dict | None = None,
    dns_analysis: dict | None = None,
    tls_analysis: dict | None = None,
    config: ReportConfig | None = None,
) -> PDFReport | None:
    """
    Convenience function to generate a PDF report.

    Args:
        report_md: LLM-generated markdown report.
        features: Extracted features dictionary.
        osint: OSINT enrichment results.
        yara_results: YARA scan results.
        dns_analysis: DNS analysis results.
        tls_analysis: TLS certificate analysis results.
        config: Optional report configuration.

    Returns:
        PDFReport object or None.
    """
    generator = PDFReportGenerator(config)
    return generator.generate(
        report_md=report_md,
        features=features,
        osint=osint,
        yara_results=yara_results,
        dns_analysis=dns_analysis,
        tls_analysis=tls_analysis,
    )
