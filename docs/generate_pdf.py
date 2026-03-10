"""
Generate ThreatFlow documentation PDF using ReportLab.
Run:  python3.12 docs/generate_pdf.py
Output: docs/ThreatFlow_Documentation.pdf
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

# ──────────────────────────────────────────────────────────────────────────────
# Colour palette
# ──────────────────────────────────────────────────────────────────────────────

NAVY    = colors.HexColor("#0d1b2a")
TEAL    = colors.HexColor("#1b7f8e")
SLATE   = colors.HexColor("#3d5a6e")
SILVER  = colors.HexColor("#dce8ed")
RED_RISK = colors.HexColor("#c0392b")
AMBER   = colors.HexColor("#e67e22")
GREEN   = colors.HexColor("#27ae60")
LIGHT_GREEN = colors.HexColor("#e8f8f0")
LIGHT_BLUE  = colors.HexColor("#eaf4f8")
LIGHT_AMBER = colors.HexColor("#fef9e7")
WHITE   = colors.white
BLACK   = colors.black

PAGE_W, PAGE_H = A4

# ──────────────────────────────────────────────────────────────────────────────
# Document class with TOC + page numbers
# ──────────────────────────────────────────────────────────────────────────────

class ThreatFlowDoc(BaseDocTemplate):
    def __init__(self, filename: str) -> None:
        super().__init__(
            filename,
            pagesize=A4,
            leftMargin=2.2 * cm,
            rightMargin=2.2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
        )
        self.toc = TableOfContents()
        self.toc.levelStyles = [
            ParagraphStyle(
                "TOC1", fontSize=11, leading=16,
                leftIndent=0, textColor=NAVY,
                fontName="Helvetica-Bold",
            ),
            ParagraphStyle(
                "TOC2", fontSize=10, leading=14,
                leftIndent=1 * cm, textColor=SLATE,
            ),
        ]
        self._build_templates()

    def _build_templates(self) -> None:
        content_frame = Frame(
            self.leftMargin, self.bottomMargin,
            PAGE_W - self.leftMargin - self.rightMargin,
            PAGE_H - self.topMargin - self.bottomMargin,
            id="normal",
        )
        self.addPageTemplates([
            PageTemplate(id="cover", frames=[content_frame], onPage=_cover_page),
            PageTemplate(id="content", frames=[content_frame], onPage=_content_page),
        ])

    def afterFlowable(self, flowable: object) -> None:
        """Register headings for TOC."""
        if isinstance(flowable, Paragraph):
            style = flowable.style.name
            text = flowable.getPlainText()
            if style == "Heading1":
                self.notify("TOCEntry", (0, text, self.page))
            elif style == "Heading2":
                self.notify("TOCEntry", (1, text, self.page))


def _cover_page(canvas, doc) -> None:
    canvas.saveState()
    # Navy header band
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - 7 * cm, PAGE_W, 7 * cm, fill=1, stroke=0)
    # Teal accent stripe
    canvas.setFillColor(TEAL)
    canvas.rect(0, PAGE_H - 7.4 * cm, PAGE_W, 0.4 * cm, fill=1, stroke=0)
    # Footer band
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, 1.8 * cm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(PAGE_W / 2, 0.7 * cm, "ThreatFlow — Vendor-Neutral SOC Response Framework")
    canvas.restoreState()


def _content_page(canvas, doc) -> None:
    canvas.saveState()
    # Top rule
    canvas.setStrokeColor(TEAL)
    canvas.setLineWidth(1.5)
    canvas.line(doc.leftMargin, PAGE_H - doc.topMargin + 0.5 * cm,
                PAGE_W - doc.rightMargin, PAGE_H - doc.topMargin + 0.5 * cm)
    # Header text
    canvas.setFillColor(SLATE)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(doc.leftMargin, PAGE_H - doc.topMargin + 0.7 * cm, "ThreatFlow Documentation")
    canvas.drawRightString(PAGE_W - doc.rightMargin, PAGE_H - doc.topMargin + 0.7 * cm, "v0.1.0")
    # Bottom rule + page number
    canvas.setStrokeColor(TEAL)
    canvas.line(doc.leftMargin, doc.bottomMargin - 0.5 * cm,
                PAGE_W - doc.rightMargin, doc.bottomMargin - 0.5 * cm)
    canvas.setFillColor(SLATE)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(PAGE_W / 2, doc.bottomMargin - 0.8 * cm, f"Page {doc.page}")
    canvas.restoreState()


# ──────────────────────────────────────────────────────────────────────────────
# Style helpers
# ──────────────────────────────────────────────────────────────────────────────

def make_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle(
            "Title", parent=base["Title"],
            fontSize=32, textColor=WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER, leading=40,
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle", fontSize=14, textColor=SLATE,
            fontName="Helvetica", alignment=TA_CENTER, leading=20,
        ),
        "CoverMeta": ParagraphStyle(
            "CoverMeta", fontSize=10, textColor=SLATE,
            fontName="Helvetica", alignment=TA_CENTER, leading=16,
        ),
        "Heading1": ParagraphStyle(
            "Heading1", fontSize=18, textColor=NAVY,
            fontName="Helvetica-Bold", spaceBefore=18, spaceAfter=8,
            leading=22,
        ),
        "Heading2": ParagraphStyle(
            "Heading2", fontSize=13, textColor=TEAL,
            fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6,
            leading=17,
        ),
        "Heading3": ParagraphStyle(
            "Heading3", fontSize=11, textColor=SLATE,
            fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4,
        ),
        "Body": ParagraphStyle(
            "Body", fontSize=10, textColor=BLACK,
            fontName="Helvetica", leading=15, spaceAfter=6,
            alignment=TA_JUSTIFY,
        ),
        "Bullet": ParagraphStyle(
            "Bullet", fontSize=10, textColor=BLACK,
            fontName="Helvetica", leading=14, spaceAfter=3,
            leftIndent=14, bulletIndent=0,
        ),
        "Code": ParagraphStyle(
            "Code", fontSize=8.5, textColor=NAVY,
            fontName="Courier", leading=13, spaceAfter=4,
            leftIndent=10, backColor=LIGHT_BLUE,
        ),
        "TableHeader": ParagraphStyle(
            "TableHeader", fontSize=9, textColor=WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
        "TableCell": ParagraphStyle(
            "TableCell", fontSize=9, textColor=BLACK,
            fontName="Helvetica", leading=13,
        ),
        "TableCode": ParagraphStyle(
            "TableCode", fontSize=8, textColor=NAVY,
            fontName="Courier",
        ),
        "Caption": ParagraphStyle(
            "Caption", fontSize=8, textColor=SLATE,
            fontName="Helvetica-Oblique", alignment=TA_CENTER,
        ),
        "TOCTitle": ParagraphStyle(
            "TOCTitle", fontSize=16, textColor=NAVY,
            fontName="Helvetica-Bold", spaceAfter=12,
        ),
        "Note": ParagraphStyle(
            "Note", fontSize=9, textColor=SLATE,
            fontName="Helvetica-Oblique", leading=13,
            leftIndent=10,
        ),
    }


S = make_styles()


def h1(text: str) -> Paragraph:
    return Paragraph(text, S["Heading1"])


def h2(text: str) -> Paragraph:
    return Paragraph(text, S["Heading2"])


def h3(text: str) -> Paragraph:
    return Paragraph(text, S["Heading3"])


def body(text: str) -> Paragraph:
    return Paragraph(text, S["Body"])


def bullet(text: str) -> Paragraph:
    return Paragraph(f"• &nbsp;{text}", S["Bullet"])


def code(text: str) -> Paragraph:
    return Paragraph(text.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"), S["Code"])


def sp(h: float = 0.3) -> Spacer:
    return Spacer(1, h * cm)


def rule() -> HRFlowable:
    return HRFlowable(width="100%", thickness=1, color=SILVER, spaceAfter=6, spaceBefore=6)


def table_style(header_rows: int = 1) -> TableStyle:
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, header_rows - 1), NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, header_rows - 1), WHITE),
        ("FONTNAME",     (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, header_rows - 1), 9),
        ("ALIGN",        (0, 0), (-1, header_rows - 1), "CENTER"),
        ("ROWBACKGROUNDS", (0, header_rows), (-1, -1), [WHITE, LIGHT_BLUE]),
        ("FONTNAME",     (0, header_rows), (-1, -1), "Helvetica"),
        ("FONTSIZE",     (0, header_rows), (-1, -1), 9),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",         (0, 0), (-1, -1), 0.4, SILVER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ])


def risk_badge(level: str) -> str:
    colour = {"low": "#27ae60", "medium": "#e67e22", "high": "#c0392b", "critical": "#7d0000"}.get(level, "#888")
    return f'<font color="{colour}"><b>{level.upper()}</b></font>'


# ──────────────────────────────────────────────────────────────────────────────
# Content builders
# ──────────────────────────────────────────────────────────────────────────────

def cover_page() -> list:
    return [
        NextPageTemplate("cover"),
        sp(5.5),
        Paragraph("ThreatFlow", S["Title"]),
        sp(0.3),
        Paragraph("Vendor-Neutral SOC Response Abstraction Framework", S["Subtitle"]),
        sp(0.5),
        rule(),
        sp(0.3),
        Paragraph("Technical Documentation &nbsp;·&nbsp; v0.1.0 &nbsp;·&nbsp; 2025", S["CoverMeta"]),
        Paragraph("Apache 2.0 &nbsp;·&nbsp; Python 3.12+", S["CoverMeta"]),
        sp(1.5),
        Paragraph(
            "ThreatFlow standardises security response actions across CrowdStrike Falcon, "
            "Microsoft Defender, Splunk SOAR, and custom tools — providing a unified schema, "
            "action catalog, playbook engine, and CLI.",
            ParagraphStyle("CoverDesc", fontSize=11, textColor=SLATE,
                           fontName="Helvetica", alignment=TA_CENTER, leading=17),
        ),
        NextPageTemplate("content"),
        PageBreak(),
    ]


def toc_section(toc: TableOfContents) -> list:
    return [
        Paragraph("Table of Contents", S["TOCTitle"]),
        rule(),
        toc,
        PageBreak(),
    ]


def section_overview() -> list:
    items = []
    items += [h1("1. Overview"), rule()]
    items.append(body(
        "ThreatFlow is the <i>Sigma for response actions</i> — an open-source, vendor-neutral "
        "framework that lets security teams define response actions once and execute them across "
        "multiple security platforms without rewriting logic per tool."
    ))
    items.append(body(
        "The framework ships with 15 built-in actions across 5 security domains, three production-"
        "ready adapter templates (CrowdStrike Falcon, Microsoft Defender + Entra ID, Splunk SOAR), "
        "a YAML playbook engine, and a full CLI. Every action is mapped to MITRE D3FEND defensive "
        "techniques and the ATT&amp;CK techniques it counters."
    ))
    items.append(sp())

    items.append(h2("1.1 What ThreatFlow Is"))
    for b in [
        "<b>Action catalog</b> — YAML-defined, vendor-neutral response actions with rich metadata",
        "<b>Provider adapters</b> — thin translation layers to each platform's native API",
        "<b>Playbook engine</b> — ordered YAML workflows with template variables and conditional steps",
        "<b>MITRE integration</b> — every action mapped to D3FEND + ATT&amp;CK (offline, no live API)",
        "<b>CLI</b> — <font face='Courier'>threatflow</font> command for operators and CI/CD pipelines",
        "<b>Extensible</b> — new adapters and actions in &lt;50 lines each",
    ]:
        items.append(bullet(b))
    items.append(sp())

    items.append(h2("1.2 What ThreatFlow Is Not"))
    for b in [
        "Not a full SOAR platform — no web UI, no event ingestion, no persistent queue",
        "Not an async distributed worker system",
        "Not a database-backed service",
    ]:
        items.append(bullet(b))
    items.append(sp())

    items.append(h2("1.3 Design Principles"))
    data = [
        [Paragraph("Principle", S["TableHeader"]), Paragraph("Implementation", S["TableHeader"])],
        [Paragraph("Vendor-neutral schema", S["TableCell"]), Paragraph("Actions defined in YAML with zero provider coupling", S["TableCell"])],
        [Paragraph("Vendor-native execution", S["TableCell"]), Paragraph("Adapters translate each action to the platform's native API call", S["TableCell"])],
        [Paragraph("D3FEND-aware", S["TableCell"]), Paragraph("Every action carries D3FEND technique mappings", S["TableCell"])],
        [Paragraph("Safe by default", S["TableCell"]), Paragraph("Risk levels and approval modes enforced on every action definition", S["TableCell"])],
        [Paragraph("Offline-first", S["TableCell"]), Paragraph("No runtime calls to MITRE APIs; bundled mapping YAML files", S["TableCell"])],
        [Paragraph("Contributor-friendly", S["TableCell"]), Paragraph("New adapter in ~50 lines; new action in ~30 lines of YAML", S["TableCell"])],
    ]
    t = Table(data, colWidths=[5.5 * cm, 11 * cm])
    t.setStyle(table_style())
    items += [t, sp()]
    return items


def section_architecture() -> list:
    items = [h1("2. Architecture"), rule()]
    items.append(body(
        "ThreatFlow follows a layered architecture. The <b>core</b> layer owns the domain models "
        "and orchestration logic. The <b>adapter</b> layer provides pluggable provider integrations. "
        "The <b>playbook</b> layer runs multi-step workflows. The <b>CLI</b> layer exposes everything "
        "to operators."
    ))
    items.append(sp())

    items.append(h2("2.1 Package Structure"))
    lines = [
        "src/threatflow/",
        "  core/           Pydantic models, ActionRegistry, CatalogLoader, ActionExecutor",
        "  adapters/       BaseAdapter + crowdstrike, defender, splunk_soar",
        "  playbook/       Playbook models, validator, executor",
        "  mappings/       Bundled MITRE ATT&CK ↔ D3FEND index",
        "  cli/            Typer CLI (actions, run, plan, playbook)",
        "",
        "catalog/",
        "  actions/        YAML action catalog (15 actions, 5 domains)",
        "  mappings/       attack.yaml, d3fend.yaml",
        "",
        "playbooks/        Example YAML playbooks",
        "schemas/          JSON schemas for validation",
        "tests/            119 unit tests",
    ]
    for line in lines:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())

    items.append(h2("2.2 Data Flow"))
    items.append(body(
        "1. <b>CatalogLoader</b> reads YAML files from <font face='Courier'>catalog/actions/</font> "
        "and populates an <b>ActionRegistry</b>.<br/>"
        "2. The <b>CLI</b> (or Python API) calls <b>ActionExecutor.execute()</b> with an action ID, "
        "provider name, and parameters.<br/>"
        "3. The executor validates inputs, enforces approval gates, then dispatches to the "
        "matching <b>provider adapter</b>.<br/>"
        "4. The adapter translates the abstract action into a native API call and returns an "
        "<b>ExecutionResult</b>.<br/>"
        "5. For playbooks, the <b>PlaybookExecutor</b> iterates steps, resolves "
        "<font face='Courier'>{{ template }}</font> variables from context, and chains step outputs."
    ))
    items.append(sp())

    items.append(h2("2.3 Core Models"))
    data = [
        [Paragraph("Model", S["TableHeader"]), Paragraph("Purpose", S["TableHeader"]), Paragraph("Key Fields", S["TableHeader"])],
        [Paragraph("Action", S["TableCell"]), Paragraph("Vendor-neutral action definition", S["TableCell"]), Paragraph("id, domain, risk_level, approval_mode, inputs, outputs, d3fend_mappings, attack_mappings", S["TableCode"])],
        [Paragraph("ExecutionResult", S["TableCell"]), Paragraph("Result of running an action", S["TableCell"]), Paragraph("success, outputs, message, error, dry_run", S["TableCode"])],
        [Paragraph("Playbook", S["TableCell"]), Paragraph("Multi-step response workflow", S["TableCell"]), Paragraph("id, inputs, steps, triggers", S["TableCode"])],
        [Paragraph("PlaybookStep", S["TableCell"]), Paragraph("Single step in a playbook", S["TableCell"]), Paragraph("action_id, provider, inputs, condition, on_failure", S["TableCode"])],
        [Paragraph("ProviderInfo", S["TableCell"]), Paragraph("Adapter metadata", S["TableCell"]), Paragraph("id, name, capabilities, config_schema", S["TableCode"])],
    ]
    t = Table(data, colWidths=[3.5 * cm, 5.5 * cm, 7.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]
    return items


def section_actions() -> list:
    items = [h1("3. Action Catalog"), rule()]
    items.append(body(
        "Actions are the atomic units of ThreatFlow. Each action is defined in YAML and is "
        "completely vendor-neutral — it describes <i>what</i> to do, not <i>how</i> a specific "
        "platform does it. Adapters handle the translation."
    ))
    items.append(sp())

    items.append(h2("3.1 Built-in Actions"))
    data = [
        [Paragraph("Domain", S["TableHeader"]), Paragraph("Action ID", S["TableHeader"]), Paragraph("Risk", S["TableHeader"]), Paragraph("Approval", S["TableHeader"]), Paragraph("Providers", S["TableHeader"])],
        # Endpoint
        [Paragraph("endpoint", S["TableCell"]), Paragraph("isolate_host", S["TableCode"]), Paragraph(risk_badge("high"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("endpoint", S["TableCell"]), Paragraph("release_host", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("endpoint", S["TableCell"]), Paragraph("kill_process", S["TableCode"]), Paragraph(risk_badge("high"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("endpoint", S["TableCell"]), Paragraph("quarantine_file", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        # Identity
        [Paragraph("identity", S["TableCell"]), Paragraph("disable_user", S["TableCode"]), Paragraph(risk_badge("high"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("defender, splunk_soar", S["TableCode"])],
        [Paragraph("identity", S["TableCell"]), Paragraph("revoke_session", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("defender, splunk_soar", S["TableCode"])],
        [Paragraph("identity", S["TableCell"]), Paragraph("reset_password", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("defender", S["TableCode"])],
        # Email
        [Paragraph("email", S["TableCell"]), Paragraph("purge_email", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("defender", S["TableCode"])],
        [Paragraph("email", S["TableCell"]), Paragraph("block_sender", S["TableCode"]), Paragraph(risk_badge("low"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("defender, splunk_soar", S["TableCode"])],
        [Paragraph("email", S["TableCell"]), Paragraph("block_domain", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("soft", S["TableCell"]), Paragraph("defender, splunk_soar", S["TableCode"])],
        # Network
        [Paragraph("network", S["TableCell"]), Paragraph("block_ip", S["TableCode"]), Paragraph(risk_badge("medium"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("network", S["TableCell"]), Paragraph("unblock_ip", S["TableCode"]), Paragraph(risk_badge("low"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        # Case
        [Paragraph("case", S["TableCell"]), Paragraph("create_case", S["TableCode"]), Paragraph(risk_badge("low"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("case", S["TableCell"]), Paragraph("append_note", S["TableCode"]), Paragraph(risk_badge("low"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
        [Paragraph("case", S["TableCell"]), Paragraph("add_artifact", S["TableCode"]), Paragraph(risk_badge("low"), S["TableCell"]), Paragraph("none", S["TableCell"]), Paragraph("crowdstrike, defender, splunk_soar", S["TableCode"])],
    ]
    t = Table(data, colWidths=[2.2 * cm, 3.5 * cm, 2 * cm, 2.3 * cm, 6.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("3.2 Action YAML Schema"))
    items.append(body("Each action is defined in a YAML file under <font face='Courier'>catalog/actions/</font>. "
                      "The following example shows the full schema:"))
    schema_lines = [
        "id: isolate_host",
        "name: Isolate Host",
        "domain: endpoint            # endpoint | identity | email | network | case",
        "description: >",
        "  Isolate a host from the network.",
        "risk_level: high            # low | medium | high | critical",
        "approval_mode: soft         # none | soft | hard",
        "supported_providers:",
        "  - crowdstrike",
        "  - defender",
        "inputs:",
        "  - name: host_id",
        "    type: string",
        "    required: true",
        "    description: Platform-specific host identifier.",
        "outputs:",
        "  - name: status",
        "    type: string",
        "    description: Isolation status.",
        "d3fend_mappings:",
        "  - technique_id: D3-NI",
        "    technique_name: Network Isolation",
        "    tactic: Isolate",
        "attack_mappings:",
        "  - technique_id: T1486",
        "    technique_name: Data Encrypted for Impact",
        "    tactic: Impact",
        "tags: [endpoint, containment]",
    ]
    for line in schema_lines:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())

    items.append(h2("3.3 Approval Modes"))
    data = [
        [Paragraph("Mode", S["TableHeader"]), Paragraph("Behaviour", S["TableHeader"]), Paragraph("CLI Override", S["TableHeader"])],
        [Paragraph("none", S["TableCode"]), Paragraph("Execute immediately, no gate", S["TableCell"]), Paragraph("N/A", S["TableCell"])],
        [Paragraph("soft", S["TableCode"]), Paragraph("Interactive confirmation prompt for operator", S["TableCell"]), Paragraph("--force bypasses", S["TableCode"])],
        [Paragraph("hard", S["TableCode"]), Paragraph("Requires out-of-band approval token", S["TableCell"]), Paragraph("Cannot be bypassed", S["TableCell"])],
    ]
    t = Table(data, colWidths=[2.5 * cm, 9.5 * cm, 4.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(Paragraph(
        "⚠  Actions with <b>critical</b> risk level are automatically upgraded to <b>soft</b> "
        "approval mode if defined with <font face='Courier'>approval_mode: none</font>.",
        S["Note"],
    ))
    items.append(sp())
    return items


def section_adapters() -> list:
    items = [h1("4. Provider Adapters"), rule()]
    items.append(body(
        "Provider adapters are the bridge between ThreatFlow abstract actions and the "
        "native APIs of each security platform. All adapters extend <font face='Courier'>BaseAdapter</font> "
        "and implement six methods."
    ))
    items.append(sp())

    items.append(h2("4.1 BaseAdapter Interface"))
    methods = [
        ("provider_info()", "Return static metadata: id, name, capabilities, config schema"),
        ("get_capabilities()", "Return list of action IDs this adapter can execute"),
        ("validate_inputs(action, params)", "Provider-specific input validation; return list of error strings"),
        ("execute(action, params)", "Execute the action via the provider API; return ExecutionResult"),
        ("dry_run(action, params)", "Simulate execution with no side-effects; return ExecutionResult with dry_run=True"),
        ("map_native_action(action)", "Return the native API call that implements this action"),
    ]
    data = [[Paragraph("Method", S["TableHeader"]), Paragraph("Purpose", S["TableHeader"])]]
    for m, p in methods:
        data.append([Paragraph(m, S["TableCode"]), Paragraph(p, S["TableCell"])])
    t = Table(data, colWidths=[7 * cm, 9.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("4.2 Built-in Adapters"))
    for adapter, provider_id, coverage, api in [
        ("CrowdStrikeAdapter", "crowdstrike",
         "isolate_host, release_host, kill_process, quarantine_file, block_ip, unblock_ip, create_case, append_note, add_artifact",
         "Falcon Hosts API, RTR Admin API, Quarantine API, Custom IOA API"),
        ("DefenderAdapter", "defender",
         "All 15 actions",
         "MDE REST API, Microsoft Graph API, Exchange Online Protection, Microsoft Sentinel"),
        ("SplunkSOARAdapter", "splunk_soar",
         "isolate_host, release_host, kill_process, quarantine_file, disable_user, block_ip, unblock_ip, block_domain, block_sender, create_case, append_note, add_artifact",
         "SOAR REST API /rest/action_run and /rest/container"),
    ]:
        items.append(h3(adapter))
        items.append(body(f"Provider ID: <font face='Courier'>{provider_id}</font>"))
        items.append(body(f"<b>Coverage:</b> {coverage}"))
        items.append(body(f"<b>Native APIs:</b> {api}"))
        items.append(Paragraph(
            "Current implementations are demo/mock adapters. Each handler documents the real API "
            "endpoint and contains <font face='Courier'># TODO: real API call</font> comments for production wiring.",
            S["Note"],
        ))
        items.append(sp(0.3))

    items.append(h2("4.3 Writing a Custom Adapter"))
    items.append(body(
        "See <font face='Courier'>examples/custom_adapter.py</font> for a complete template. "
        "The minimum implementation:"
    ))
    impl_lines = [
        "from threatflow.adapters.base import BaseAdapter, NativeActionMapping",
        "from threatflow.core.models import Action, ExecutionResult, ProviderInfo",
        "",
        "class MyAdapter(BaseAdapter):",
        "    PROVIDER_ID = 'my_platform'",
        "",
        "    def provider_info(self) -> ProviderInfo: ...",
        "    def get_capabilities(self) -> list[str]: ...",
        "    def validate_inputs(self, action, params) -> list[str]: ...",
        "    def execute(self, action, params) -> ExecutionResult: ...",
        "    def dry_run(self, action, params) -> ExecutionResult: ...",
        "    def map_native_action(self, action) -> NativeActionMapping: ...",
        "",
        "# Register with executor:",
        "executor.register_adapter('my_platform', MyAdapter(config={...}))",
    ]
    for line in impl_lines:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())
    return items


def section_playbooks() -> list:
    items = [h1("5. Playbook Engine"), rule()]
    items.append(body(
        "Playbooks are YAML files that sequence multiple actions into a response workflow. "
        "The playbook engine supports template variable substitution, conditional step execution, "
        "step-output chaining, and configurable failure behaviour."
    ))
    items.append(sp())

    items.append(h2("5.1 Playbook Structure"))
    pb_lines = [
        "id: ransomware_response",
        "name: Ransomware Incident Response",
        "version: '1.0.0'",
        "severity: critical",
        "triggers: [T1486]",
        "",
        "inputs:",
        "  - name: host_id",
        "    type: string",
        "    required: true",
        "  - name: c2_ip",
        "    required: false",
        "    default: ''",
        "",
        "steps:",
        "  - id: create_case",
        "    action_id: create_case",
        "    provider: crowdstrike",
        "    inputs:",
        "      title: 'Ransomware — Active Encryption'",
        "      severity: critical",
        "    on_failure: stop",
        "",
        "  - id: isolate_host",
        "    action_id: isolate_host",
        "    provider: crowdstrike",
        "    inputs:",
        "      host_id: '{{ host_id }}'",
        "      comment: 'Case {{ create_case.case_id }}'",
        "    on_failure: stop",
        "",
        "  - id: block_c2",
        "    action_id: block_ip",
        "    provider: crowdstrike",
        "    condition: \"c2_ip != ''\"",
        "    inputs:",
        "      ip_address: '{{ c2_ip }}'",
        "    on_failure: continue",
    ]
    for line in pb_lines:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())

    items.append(h2("5.2 Template Variables"))
    data = [
        [Paragraph("Syntax", S["TableHeader"]), Paragraph("Resolves To", S["TableHeader"]), Paragraph("Example", S["TableHeader"])],
        [Paragraph("{{ variable }}", S["TableCode"]), Paragraph("Playbook input value", S["TableCell"]), Paragraph("{{ host_id }}", S["TableCode"])],
        [Paragraph("{{ step_id.key }}", S["TableCode"]), Paragraph("Output field from a previous step", S["TableCell"]), Paragraph("{{ create_case.case_id }}", S["TableCode"])],
    ]
    t = Table(data, colWidths=[4 * cm, 6 * cm, 6.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("5.3 Step Failure Modes"))
    data = [
        [Paragraph("on_failure", S["TableHeader"]), Paragraph("Behaviour", S["TableHeader"])],
        [Paragraph("stop", S["TableCode"]), Paragraph("Halt the playbook immediately and report failure", S["TableCell"])],
        [Paragraph("continue", S["TableCode"]), Paragraph("Log the error, mark step failed, proceed to next step", S["TableCell"])],
        [Paragraph("skip", S["TableCode"]), Paragraph("Mark step skipped, continue as if it succeeded", S["TableCell"])],
    ]
    t = Table(data, colWidths=[3 * cm, 13.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("5.4 Bundled Playbooks"))
    data = [
        [Paragraph("Playbook", S["TableHeader"]), Paragraph("Triggers", S["TableHeader"]), Paragraph("Steps", S["TableHeader"]), Paragraph("Provider", S["TableHeader"])],
        [Paragraph("ransomware_response", S["TableCode"]), Paragraph("T1486", S["TableCell"]), Paragraph("7", S["TableCell"]), Paragraph("crowdstrike", S["TableCode"])],
        [Paragraph("phishing_response", S["TableCode"]), Paragraph("T1566, T1566.001", S["TableCell"]), Paragraph("7", S["TableCell"]), Paragraph("defender", S["TableCode"])],
        [Paragraph("compromised_account_response", S["TableCode"]), Paragraph("T1078, T1110, T1550", S["TableCell"]), Paragraph("9", S["TableCell"]), Paragraph("defender", S["TableCode"])],
    ]
    t = Table(data, colWidths=[5.5 * cm, 4.5 * cm, 2 * cm, 4.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]
    return items


def section_mitre() -> list:
    items = [h1("6. MITRE Integration"), rule()]
    items.append(body(
        "ThreatFlow embeds both MITRE ATT&amp;CK and D3FEND technique data as bundled YAML files, "
        "enabling offline operation and predictable behaviour in air-gapped environments. "
        "No runtime calls to the MITRE TAXII server are made."
    ))
    items.append(sp())

    items.append(h2("6.1 D3FEND Mappings"))
    items.append(body(
        "Every action definition includes a <font face='Courier'>d3fend_mappings</font> list "
        "that references the D3FEND defensive techniques the action implements."
    ))
    data = [
        [Paragraph("D3FEND ID", S["TableHeader"]), Paragraph("Technique", S["TableHeader"]), Paragraph("Tactic", S["TableHeader"]), Paragraph("Actions", S["TableHeader"])],
        [Paragraph("D3-NI", S["TableCode"]), Paragraph("Network Isolation", S["TableCell"]), Paragraph("Isolate", S["TableCell"]), Paragraph("isolate_host, release_host", S["TableCode"])],
        [Paragraph("D3-PT", S["TableCode"]), Paragraph("Process Termination", S["TableCell"]), Paragraph("Evict", S["TableCell"]), Paragraph("kill_process", S["TableCode"])],
        [Paragraph("D3-UAP", S["TableCode"]), Paragraph("User Account Permissions", S["TableCell"]), Paragraph("Harden", S["TableCell"]), Paragraph("disable_user, revoke_session", S["TableCode"])],
        [Paragraph("D3-CR", S["TableCode"]), Paragraph("Credential Reset", S["TableCell"]), Paragraph("Restore", S["TableCell"]), Paragraph("reset_password", S["TableCode"])],
        [Paragraph("D3-MFD", S["TableCode"]), Paragraph("Message Filtering", S["TableCell"]), Paragraph("Harden", S["TableCell"]), Paragraph("purge_email, block_sender, block_domain", S["TableCode"])],
        [Paragraph("D3-IB", S["TableCode"]), Paragraph("IP Blacklisting", S["TableCell"]), Paragraph("Isolate", S["TableCell"]), Paragraph("block_ip", S["TableCode"])],
        [Paragraph("D3-NTF", S["TableCode"]), Paragraph("Network Traffic Filtering", S["TableCell"]), Paragraph("Harden", S["TableCell"]), Paragraph("block_ip", S["TableCode"])],
    ]
    t = Table(data, colWidths=[2.5 * cm, 4 * cm, 2.5 * cm, 7.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("6.2 ATT&CK Mappings"))
    items.append(body(
        "Each action also lists the ATT&amp;CK techniques it is designed to counter via "
        "<font face='Courier'>attack_mappings</font>. The <font face='Courier'>threatflow plan</font> "
        "command uses this cross-reference to suggest actions given a technique ID."
    ))
    items.append(sp())

    items.append(h2("6.3 Plan Command"))
    items.append(body("Given a technique ID, ThreatFlow recommends relevant response actions:"))
    for line in ["$ threatflow plan --attack-technique T1486", "", "ATT&CK Technique: T1486 — Data Encrypted for Impact", "D3FEND Countermeasures: D3-NI (Network Isolation)", "", "Recommended Actions:", "  isolate_host  endpoint  high  crowdstrike, defender, splunk_soar"]:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())
    return items


def section_cli() -> list:
    items = [h1("7. CLI Reference"), rule()]
    items.append(body(
        "The <font face='Courier'>threatflow</font> CLI is built with Typer and provides "
        "rich terminal output via Rich. All commands support <font face='Courier'>--help</font>."
    ))
    items.append(sp())

    commands = [
        ("threatflow actions list", "[--domain D] [--provider P] [--tag T] [--risk R]", "List catalog actions with optional filters"),
        ("threatflow actions show <id>", "", "Show full action detail: inputs, outputs, MITRE mappings"),
        ("threatflow run <action_id>", "--provider P [--param k=v ...] [--inputs-file f.json] [--dry-run] [--force]", "Execute a single action; --dry-run simulates, --force bypasses soft approval"),
        ("threatflow plan", "--attack-technique T1486 [--provider P]", "Suggest response actions for an ATT&CK technique"),
        ("threatflow playbook validate <file>", "", "Validate a playbook YAML without executing anything"),
        ("threatflow playbook run <file>", "--inputs f.json [--dry-run] [--force]", "Run a playbook; --dry-run simulates all steps"),
    ]
    data = [[Paragraph("Command", S["TableHeader"]), Paragraph("Key Options", S["TableHeader"]), Paragraph("Description", S["TableHeader"])]]
    for cmd, opts, desc in commands:
        data.append([Paragraph(cmd, S["TableCode"]), Paragraph(opts, S["TableCode"]), Paragraph(desc, S["TableCell"])])
    t = Table(data, colWidths=[5 * cm, 5 * cm, 6.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("7.1 Examples"))
    examples = [
        "# Browse the catalog",
        "threatflow actions list --domain endpoint",
        "threatflow actions show isolate_host",
        "",
        "# Dry-run a single action",
        "threatflow run block_ip --provider crowdstrike \\",
        "    --param ip_address=198.51.100.42 --dry-run",
        "",
        "# Execute with force (bypass soft approval)",
        "threatflow run disable_user --provider defender \\",
        "    --param user_upn=jdoe@corp.com --force",
        "",
        "# Plan a response",
        "threatflow plan --attack-technique T1566 --provider defender",
        "",
        "# Validate and run a playbook",
        "threatflow playbook validate playbooks/ransomware_response.yaml",
        "threatflow playbook run playbooks/ransomware_response.yaml \\",
        "    --inputs incident.json --dry-run",
    ]
    for line in examples:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())

    items.append(h2("7.2 Environment Variables"))
    data = [
        [Paragraph("Variable", S["TableHeader"]), Paragraph("Default", S["TableHeader"]), Paragraph("Description", S["TableHeader"])],
        [Paragraph("THREATFLOW_CATALOG_DIR", S["TableCode"]), Paragraph("./catalog/actions", S["TableCode"]), Paragraph("Override the action catalog directory", S["TableCell"])],
        [Paragraph("THREATFLOW_MAPPINGS_DIR", S["TableCode"]), Paragraph("./catalog/mappings", S["TableCode"]), Paragraph("Override the MITRE mappings directory", S["TableCell"])],
    ]
    t = Table(data, colWidths=[5.5 * cm, 4 * cm, 7 * cm])
    t.setStyle(table_style())
    items += [t, sp()]
    return items


def section_installation() -> list:
    items = [h1("8. Installation & Setup"), rule()]

    items.append(h2("8.1 Requirements"))
    for b in ["Python 3.12+", "pip / hatchling"]:
        items.append(bullet(b))
    items.append(sp(0.3))

    items.append(h2("8.2 Install from Source"))
    for line in [
        "git clone https://github.com/yunkewang/ThreatFlow",
        "cd ThreatFlow",
        "pip install -e '.[dev]'",
        "",
        "# Verify",
        "threatflow --version",
        "pytest  # 119 tests should pass",
    ]:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())

    items.append(h2("8.3 Python API Quick Start"))
    for line in [
        "from threatflow.core.loader import CatalogLoader",
        "from threatflow.core.executor import ActionExecutor",
        "from threatflow.adapters.crowdstrike import CrowdStrikeAdapter",
        "",
        "registry = CatalogLoader().load_default_catalog()",
        "executor = ActionExecutor(registry)",
        "executor.register_adapter('crowdstrike', CrowdStrikeAdapter())",
        "",
        "result = executor.execute(",
        "    'isolate_host',",
        "    provider='crowdstrike',",
        "    params={'host_id': 'abc123...'},",
        "    dry_run=True,",
        ")",
        "print(result.success, result.outputs)",
    ]:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())
    return items


def section_testing() -> list:
    items = [h1("9. Testing"), rule()]
    items.append(body(
        "ThreatFlow ships with 119 unit tests covering all core components. "
        "Tests are written with pytest and use fixtures defined in <font face='Courier'>tests/conftest.py</font>."
    ))
    items.append(sp())

    items.append(h2("9.1 Test Coverage"))
    data = [
        [Paragraph("Test File", S["TableHeader"]), Paragraph("Tests", S["TableHeader"]), Paragraph("Covers", S["TableHeader"])],
        [Paragraph("test_models.py", S["TableCode"]), Paragraph("22", S["TableCell"]), Paragraph("Action, ExecutionResult, D3FENDMapping, ATTACKMapping, ValidationResult", S["TableCell"])],
        [Paragraph("test_registry.py", S["TableCode"]), Paragraph("20", S["TableCell"]), Paragraph("ActionRegistry — CRUD, filter, ATT&CK/D3FEND lookup", S["TableCell"])],
        [Paragraph("test_loader.py", S["TableCode"]), Paragraph("12", S["TableCell"]), Paragraph("CatalogLoader — YAML parsing, directory loading, error handling", S["TableCell"])],
        [Paragraph("test_executor.py", S["TableCode"]), Paragraph("15", S["TableCell"]), Paragraph("ActionExecutor — validation, approval gates, dry-run, error cases", S["TableCell"])],
        [Paragraph("test_adapters.py", S["TableCode"]), Paragraph("33", S["TableCell"]), Paragraph("All three adapters — contract tests + action-specific tests", S["TableCell"])],
        [Paragraph("test_playbook.py", S["TableCode"]), Paragraph("17", S["TableCell"]), Paragraph("Playbook models, validator, executor — including conditional steps", S["TableCell"])],
    ]
    t = Table(data, colWidths=[4 * cm, 2 * cm, 10.5 * cm])
    t.setStyle(table_style())
    items += [t, sp()]

    items.append(h2("9.2 Running Tests"))
    for line in [
        "pytest                                    # all tests",
        "pytest tests/test_adapters.py -v         # single file",
        "pytest --cov=threatflow --cov-report=term-missing",
    ]:
        items.append(Paragraph(
            line.replace(" ", "&nbsp;").replace("<", "&lt;").replace(">", "&gt;"),
            S["Code"],
        ))
    items.append(sp())
    return items


def section_contributing() -> list:
    items = [h1("10. Contributing"), rule()]
    items.append(body(
        "ThreatFlow is designed to be contributor-friendly. The three most common "
        "contribution types are adding catalog actions, writing provider adapters, "
        "and creating playbooks. See <font face='Courier'>CONTRIBUTING.md</font> for full details."
    ))
    items.append(sp())

    items.append(h2("10.1 Adding a Catalog Action"))
    for b in [
        "Verify the action is vendor-neutral (implementable by 2+ providers)",
        "Identify the relevant D3FEND and ATT&CK technique mappings",
        "Add a YAML entry to the appropriate domain file under catalog/actions/",
        "Run threatflow actions list to verify it loads",
        "Add the action ID to any adapter that implements it",
    ]:
        items.append(bullet(b))
    items.append(sp(0.3))

    items.append(h2("10.2 Writing a Provider Adapter"))
    for b in [
        "Create src/threatflow/adapters/my_platform/__init__.py and adapter.py",
        "Subclass BaseAdapter and implement all 6 methods",
        "Start with mock implementations; add # TODO: real API call comments",
        "Register in src/threatflow/cli/_registry.py",
        "Write tests following tests/test_adapters.py patterns",
    ]:
        items.append(bullet(b))
    items.append(sp(0.3))

    items.append(h2("10.3 Roadmap Highlights"))
    items.append(body("The roadmap (roadmap.md) tracks planned features across milestones:"))
    data = [
        [Paragraph("Milestone", S["TableHeader"]), Paragraph("Key Features", S["TableHeader"])],
        [Paragraph("v0.2", S["TableCell"]), Paragraph("Real CrowdStrike + Defender API integration; provider config file support", S["TableCell"])],
        [Paragraph("v0.3", S["TableCell"]), Paragraph("Playbook retry/timeout, parallel steps, rollback support", S["TableCell"])],
        [Paragraph("v0.4", S["TableCell"]), Paragraph("Cloud domain actions (AWS, Azure, GCP); threat intel domain", S["TableCell"])],
        [Paragraph("v0.5", S["TableCell"]), Paragraph("Cortex XSOAR, SentinelOne, Tines, JIRA adapters", S["TableCell"])],
        [Paragraph("v1.0", S["TableCell"]), Paragraph("Stable API, PyPI release, CACAO export, audit log (OCSF)", S["TableCell"])],
    ]
    t = Table(data, colWidths=[2.5 * cm, 14 * cm])
    t.setStyle(table_style())
    items += [t, sp()]
    return items


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def build_pdf(output_path: str) -> None:
    doc = ThreatFlowDoc(output_path)

    story = []
    story += cover_page()
    story += toc_section(doc.toc)
    story += section_overview()
    story += [PageBreak()]
    story += section_architecture()
    story += [PageBreak()]
    story += section_actions()
    story += [PageBreak()]
    story += section_adapters()
    story += [PageBreak()]
    story += section_playbooks()
    story += [PageBreak()]
    story += section_mitre()
    story += [PageBreak()]
    story += section_cli()
    story += [PageBreak()]
    story += section_installation()
    story += [PageBreak()]
    story += section_testing()
    story += [PageBreak()]
    story += section_contributing()

    doc.multiBuild(story)
    print(f"PDF generated: {output_path}")


if __name__ == "__main__":
    out_dir = Path(__file__).parent
    out_dir.mkdir(exist_ok=True)
    build_pdf(str(out_dir / "ThreatFlow_Documentation.pdf"))
