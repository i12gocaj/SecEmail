"""Tests del módulo de tracking: tokenize_url / tokenize_html / report agregado."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from secemail.tracking import (
    Tracker,
    build_campaign_report,
    render_campaign_report,
)


def test_tokenize_url_appends_token_param_and_persists(tmp_path):
    storage = tmp_path / "tracking.jsonl"
    tracker = Tracker(storage_path=storage)

    url = tracker.tokenize_url("https://lure.example/login", "victim@example.com")

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    assert "t" in qs
    token = qs["t"][0]
    assert re.match(r"^[0-9a-f]{32}$", token)

    # JSONL persistido
    entries = [json.loads(l) for l in storage.read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 1
    assert entries[0]["token"] == token
    assert entries[0]["target_email"] == "victim@example.com"
    assert entries[0]["lure_url"] == "https://lure.example/login"


def test_tokenize_url_preserves_existing_query_string(tmp_path):
    tracker = Tracker(storage_path=tmp_path / "tracking.jsonl")
    url = tracker.tokenize_url("https://lure.example/path?utm=foo", "v@example.com")
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    assert qs.get("utm") == ["foo"]
    assert "t" in qs


def test_tokenize_html_replaces_placeholders(tmp_path):
    storage = tmp_path / "tracking.jsonl"
    tracker = Tracker(storage_path=storage)

    html_in = (
        "<html><body><a href='{{LURE_URL}}'>haz clic</a>"
        "<img src='{{PIXEL_URL}}'>"
        "<p>{{TARGET_EMAIL}}</p>"
        "<p>{{TOKEN}}</p>"
        "</body></html>"
    )

    out = tracker.tokenize_html(
        html_in,
        target_email="victim@example.com",
        capture_base_url="https://lure.example",
        lure_url="https://phish-landing.example/login",
    )

    assert "{{LURE_URL}}" not in out
    assert "{{PIXEL_URL}}" not in out
    assert "{{TARGET_EMAIL}}" not in out
    assert "{{TOKEN}}" not in out
    assert "victim@example.com" in out

    # Pixel + click apuntan al capture base
    assert "https://lure.example/pixel/" in out
    assert "https://lure.example/click/" in out
    # URL del lure queda en el querystring del click
    assert "phish-landing.example" in out


def test_tokenize_html_without_lure_url_uses_lure_endpoint(tmp_path):
    tracker = Tracker(storage_path=tmp_path / "tracking.jsonl")
    html_in = "<a href='{{LURE_URL}}'>x</a><img src='{{PIXEL_URL}}'>"
    out = tracker.tokenize_html(
        html_in,
        target_email="v@example.com",
        capture_base_url="https://lure.example/",
    )
    assert "https://lure.example/lure/" in out


def test_tokenize_html_with_explicit_token_does_not_persist_again(tmp_path):
    storage = tmp_path / "tracking.jsonl"
    tracker = Tracker(storage_path=storage)

    # 1) Crear token externamente
    token = tracker.tokenize_for("v@example.com", capture_base_url="https://lure.example")
    assert storage.read_text(encoding="utf-8").count("\n") == 1

    # 2) Reusar el mismo token
    tracker.tokenize_html(
        "<img src='{{PIXEL_URL}}'>",
        target_email="v@example.com",
        capture_base_url="https://lure.example",
        token=token,
    )
    # No se debe escribir un nuevo entry
    assert storage.read_text(encoding="utf-8").count("\n") == 1


def test_load_mapping_round_trips(tmp_path):
    storage = tmp_path / "tracking.jsonl"
    tracker = Tracker(storage_path=storage)
    tracker.tokenize_for("a@example.com", notes={"session_id": "X"})
    tracker.tokenize_for("b@example.com", notes={"session_id": "X"})

    mapping = tracker.load_mapping()
    assert len(mapping) == 2
    emails = sorted(entry.target_email for entry in mapping.values())
    assert emails == ["a@example.com", "b@example.com"]


def test_build_campaign_report_aggregates_metrics(tmp_path, monkeypatch):
    tracking = tmp_path / "tracking.jsonl"
    captures = tmp_path / "captures.jsonl"

    tracker = Tracker(storage_path=tracking)
    t1 = tracker.tokenize_for("a@example.com", notes={"session_id": "S1"})
    t2 = tracker.tokenize_for("b@example.com", notes={"session_id": "S1"})
    t3 = tracker.tokenize_for("c@example.com", notes={"session_id": "S1"})

    # Eventos simulados: a abrió + click, b solo abrió, c submitió.
    with captures.open("w", encoding="utf-8") as fh:
        for tok, ev in [(t1, "open"), (t1, "click"), (t2, "open"), (t3, "submit")]:
            fh.write(
                json.dumps(
                    {
                        "ts_utc": "2026-01-01T00:00:00Z",
                        "event": ev,
                        "token": tok,
                        "client_ip": "127.0.0.1",
                        "user_agent": "test",
                    }
                )
                + "\n"
            )

    rep = build_campaign_report(
        tracking_path=tracking, captures_path=captures, session_id="S1"
    )

    totals = rep["totals"]
    assert totals["recipients"] == 3
    assert totals["opens"] == 2
    assert totals["clicks"] == 1
    assert totals["submits"] == 1
    # Rate strings non-empty
    assert "%" in totals["open_rate"]

    text = render_campaign_report(rep)
    assert "S1" in text
    assert "a@example.com" in text


# ---------------------------------------------------------------------------
# Tests de integración plantilla ↔ tracker.
# Verifican que las plantillas distribuidas en phishing_templates/ usan los
# placeholders canónicos y que tokenize_html los sustituye todos.
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent.parent / "phishing_templates"
_TRACKING_PLACEHOLDERS = ("{{LURE_URL}}", "{{PIXEL_URL}}", "{{CLICK_URL}}", "{{TARGET_EMAIL}}", "{{TOKEN}}")


def _list_template_files() -> list:
    return sorted(_TEMPLATES_DIR.glob("*.html"))


def test_phishing_templates_exist():
    """Sanity: el directorio de plantillas no está vacío."""
    templates = _list_template_files()
    assert templates, f"No hay plantillas .html en {_TEMPLATES_DIR}"


@pytest.mark.parametrize(
    "template_path",
    _list_template_files(),
    ids=lambda p: p.name,
)
def test_template_tracking_placeholders_substituted(tmp_path, template_path):
    """Cada plantilla debe sustituir todos los placeholders de tracking sin dejar restos."""
    html = template_path.read_text(encoding="utf-8")
    tracker = Tracker(storage_path=tmp_path / "tracking.jsonl")
    rendered = tracker.tokenize_html(
        html=html,
        target_email="victim@acme-corp.example",
        capture_base_url="https://lure.operator.example",
        lure_url="https://aitm.operator.example/login",
    )
    leftover = [p for p in _TRACKING_PLACEHOLDERS if p in rendered]
    assert not leftover, (
        f"Plantilla {template_path.name} dejó placeholders de tracking sin sustituir: {leftover}. "
        "Asegúrate de usar {{LURE_URL}}, {{PIXEL_URL}}, {{CLICK_URL}}, {{TARGET_EMAIL}} o {{TOKEN}}."
    )
    assert "victim@acme-corp.example" in rendered, "TARGET_EMAIL debe acabar en el HTML renderizado"


@pytest.mark.parametrize(
    "template_path",
    _list_template_files(),
    ids=lambda p: p.name,
)
def test_template_no_external_assets(template_path):
    """Las plantillas no deben cargar recursos externos (CSS/fonts/imágenes desde HTTP).
    
    La única referencia externa permitida es el tracking pixel placeholder, que se
    sustituye runtime y apunta a la infra propia del operador (https://lure...)."""
    text = template_path.read_text(encoding="utf-8")
    # Quitar el placeholder (será sustituido a runtime).
    text_clean = text.replace("{{PIXEL_URL}}", "")
    # Buscar referencias HTTP en src/href/url() sin parametrizar.
    forbidden = re.findall(r"""(?:src|href)\s*=\s*['"]https?://[^'"]+""", text_clean)
    # Permitimos http://www.w3.org y placeholders {{...}} pero no URLs concretas a CDN externos.
    real_externals = [m for m in forbidden if "{{" not in m and "w3.org" not in m]
    assert not real_externals, (
        f"Plantilla {template_path.name} carga recursos externos: {real_externals}. "
        "Todo CSS y assets debe ir inline para evitar huella forense."
    )
    # Tampoco @font-face url(https://...).
    fontface = re.findall(r"@font-face[^}]*url\s*\(\s*['\"]?https?://[^)]+", text_clean)
    assert not fontface, f"Plantilla {template_path.name} usa @font-face externo: {fontface}"


@pytest.mark.parametrize(
    "template_path",
    _list_template_files(),
    ids=lambda p: p.name,
)
def test_template_no_real_brand_mentions(template_path):
    """Las plantillas NO deben mencionar marcas registradas reales pixel-perfect.
    
    Permitimos nombres de fuentes (Segoe UI, Roboto) porque son CSS estándar
    universal, pero NO menciones explícitas en texto de la marca propietaria."""
    text = template_path.read_text(encoding="utf-8")
    # Quitar font-family declarations para no falsos positivos con Segoe UI / SF Mono / Roboto.
    text_no_fonts = re.sub(r"font-family\s*:[^;]+;?", "", text, flags=re.IGNORECASE)
    forbidden_brands = [
        "paypal", "amazon", "google", "microsoft", "outlook", "gmail",
        "sharepoint", "docusign", "teams", "zoom", "adobe", "linkedin",
    ]
    hits = []
    lower = text_no_fonts.lower()
    for brand in forbidden_brands:
        if brand in lower:
            hits.append(brand)
    assert not hits, (
        f"Plantilla {template_path.name} menciona marcas registradas: {hits}. "
        "Usa términos genéricos (Autenticador, Plataforma de firmas, etc.)."
    )
