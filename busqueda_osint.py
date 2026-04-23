#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          OSINT CON ESTEROIDES — Pipeline Automatizado con IA                ║
║          Objetivo: dominio_empresa                                    ║
║          Técnicas: Pasivas + Semi-activas (sin tráfico directo al objetivo) ║
╚══════════════════════════════════════════════════════════════════════════════╝

INSTALACIÓN:
    pip install requests beautifulsoup4 dnspython colorama tqdm python-dotenv

USO:
    1. Copia el archivo .env.example → .env
    2. Rellena tus API keys en .env
    3. python busqueda_osint.py

    El .env debe estar en el mismo directorio que este script.
    NUNCA subas el .env a git — está en .gitignore por defecto.

MÓDULOS:
    1. DNS Recon              — registros A, MX, TXT, NS
    2. Email Harvesting       — Hunter.io API
    3. Wayback Machine        — endpoints y rutas históricas
    4. S3/GCS Bucket Check    — almacenamiento cloud expuesto
    5. GitHub Dorks           — credenciales y secretos en código
    6. VirusTotal Graph       — relaciones de dominio/IP
    7. HuggingFace NER        — extracción de entidades con IA
    8. HuggingFace Classify   — clasificación zero-shot de riesgos
    9. AI Correlation         — síntesis inteligente de hallazgos
    10. Report Generation      — reporte Markdown ejecutivo
"""

import os
import re
import json
import time
import socket
import hashlib
import logging
import datetime
import ipaddress
from pathlib import Path
from typing import Optional
from collections import defaultdict

import requests
from colorama import Fore, Style, init as colorama_init

# ─── Carga de variables de entorno desde .env ────────────────────────────────
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=True)
        print(f"[dotenv] .env cargado desde {_env_path}")
    else:
        print(f"[dotenv] Advertencia: .env no encontrado en {_env_path}")
        print("         Copia .env.example a .env y rellena tus keys.")
except ImportError:
    print("[dotenv] python-dotenv no instalado — ejecuta: pip install python-dotenv")
    print("         Continuando sin .env; las keys deben estar en el entorno.")

# ─── Inicialización ──────────────────────────────────────────────────────────
colorama_init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("osint_run.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("OSINT")

# ─── Configuración — todo se deriva de target_domain en .env ─────────────────
#
# La ÚNICA variable obligatoria es target_domain en .env:
#
#   target_domain=bridgefundinggroupinc.com
#
# A partir de ella el script genera automáticamente:
#   • target_org        → parte antes del primer punto, sin TLD
#   • target_apex       → dominio raíz (sin subdominios)
#   • target_variants   → variantes comunes del dominio
#   • bucket_variants   → nombres de bucket cloud derivados del org
#   • org_slug          → slug para búsquedas (sin puntos ni guiones)

def _derive_targets(domain: str) -> dict:
    """Genera todos los targets derivados a partir del dominio base."""
    domain = domain.strip().lower().lstrip("www.")

    # Partes del dominio: "bridge-funding-group.com" → ["bridge-funding-group", "com"]
    parts = domain.split(".")
    apex  = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    # Nombre sin TLD: "bridge-funding-group"
    name  = parts[-2] if len(parts) >= 2 else parts[0]
    # Slug sin guiones ni puntos: "bridgefundinggroup"
    slug  = name.replace("-", "").replace("_", "")
    # TLD
    tld   = parts[-1] if len(parts) >= 2 else "com"

    # Variantes de dominio: dominio principal + alternativas con/sin guiones
    name_nodash = name.replace("-", "")
    variants = list(dict.fromkeys([          # preserva orden, elimina dupes
        apex,
        f"{name_nodash}.{tld}",
        f"{name}.{tld}",
        f"www.{apex}",
    ]))

    # Variantes de bucket: slug + variaciones con guiones y sufijos comunes
    bucket_base = [
        slug,
        name,
        name_nodash,
        f"{slug}-inc",
        f"{name}-inc",
        f"{slug}-docs",
        f"{slug}-assets",
        f"{slug}-data",
        f"{slug}-backup",
        f"{slug}-prod",
        f"{slug}-dev",
        f"{slug}-staging",
        f"{name}-assets",
        f"{name}-data",
    ]
    bucket_variants = list(dict.fromkeys(bucket_base))  # elimina dupes

    return {
        "target_domain":   apex,
        "target_org":      name,          # "bridge-funding-group"
        "target_slug":     slug,          # "bridgefundinggroup"  (sin guiones)
        "target_tld":      tld,
        "target_variants": variants,
        "bucket_variants": bucket_variants,
    }


# Lee el dominio base desde .env (variable: target_domain)
_raw_domain = os.getenv("target_domain", "").strip()
if not _raw_domain:
    print(f"\n[ERROR] La variable 'target_domain' no está definida en .env")
    print("        Agrega esta línea en tu archivo .env y vuelve a ejecutar:")
    print("            target_domain=tudominio.com\n")
    raise SystemExit(1)

_targets = _derive_targets(_raw_domain)

CONFIG = {
    **_targets,   # inyecta target_domain, target_org, target_slug, variants, buckets

    # ── API Keys — todas leídas desde .env ──────────────────────────────
    # Configura en .env.example → .env  (nunca hardcodear en el código)
    "hf_token":       os.getenv("HF_TOKEN", ""),        # huggingface.co/settings/tokens
    "hunter_key":     os.getenv("HUNTER_KEY", ""),      # hunter.io/api-keys
    "virustotal_key": os.getenv("VIRUSTOTAL_KEY", ""),  # virustotal.com/gui/my-apikey
    "github_token":   os.getenv("GITHUB_TOKEN", ""),    # github.com/settings/tokens

    # ── Timeouts y throttling ───────────────────────────────────────────
    "request_timeout": 15,
    "delay_between_requests": 1.2,   # segundos — ser respetuoso con las APIs
}

REPORT = {
    "metadata": {
        "target": CONFIG["target_org"],
        "domain": CONFIG["target_domain"],
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "analyst": "OSINT-Pipeline-AI",
    },
    "subdomains": [],
    "dns_records": {},
    "emails": [],
    "wayback_endpoints": [],
    "shodan_results": {},
    "exposed_buckets": [],
    "github_findings": [],
    "virustotal": {},
    "entities": defaultdict(list),
    "risk_classifications": [],
    "ai_summary": "",
    "shadow_it": [],
    "findings": [],
}

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (compatible; SecurityResearcher/1.0; OSINT-audit)",
})


# ─── Utilidades ──────────────────────────────────────────────────────────────

def banner(title: str):
    width = 72
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  {Fore.WHITE}{Style.BRIGHT}{title}")
    print(f"{Fore.CYAN}{'═' * width}{Style.RESET_ALL}")


def ok(msg: str):
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warn(msg: str):
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def info(msg: str):
    print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def err(msg: str):
    print(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")


def get(url: str, params: dict = None, headers: dict = None,
        timeout: int = None) -> Optional[requests.Response]:
    """GET con manejo de errores y rate limiting."""
    try:
        time.sleep(CONFIG["delay_between_requests"])
        r = SESSION.get(
            url,
            params=params,
            headers=headers,
            timeout=timeout or CONFIG["request_timeout"],
        )
        return r
    except requests.RequestException as e:
        err(f"Request failed [{url[:60]}]: {e}")
        return None


def hf_inference(model: str, payload: dict) -> Optional[dict]:
    """Llama a la Inference API de HuggingFace."""
    if not CONFIG["hf_token"]:
        warn("HF_TOKEN no configurado — omitiendo inferencia IA")
        return None
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {CONFIG['hf_token']}"}
    try:
        time.sleep(0.5)
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code == 503:
            info("Modelo cargando, esperando 20s...")
            time.sleep(20)
            r = requests.post(url, headers=headers, json=payload, timeout=60)
        return r.json()
    except Exception as e:
        err(f"HuggingFace error [{model}]: {e}")
        return None


def add_finding(title: str, description: str, risk: str, source: str,
                evidence: str = ""):
    REPORT["findings"].append({
        "title": title,
        "description": description,
        "risk": risk,          # CRITICAL / HIGH / MEDIUM / LOW / INFO
        "source": source,
        "evidence": evidence,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
    })

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — Reconocimiento DNS
# ═══════════════════════════════════════════════════════════════════════════════

def dns_recon():
    banner("MÓDULO  — Reconocimiento DNS")
    domain = CONFIG["target_domain"]
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results = {}

    for rtype in record_types:
        info(f"Consultando registros {rtype} para {domain}")
        # Usar Google DNS-over-HTTPS (no requiere librería dns)
        r = get(
            "https://dns.google/resolve",
            params={"name": domain, "type": rtype},
        )
        if not r:
            continue
        try:
            data = r.json()
            answers = data.get("Answer", [])
            if answers:
                values = [a["data"] for a in answers]
                results[rtype] = values
                ok(f"  {rtype}: {', '.join(values[:3])}")
        except Exception:
            pass

    # Análisis de registros TXT para tecnologías
    txt_records = results.get("TXT", [])
    tech_indicators = {
        "v=spf1":         "SPF configurado",
        "google-site-verification": "Google Workspace / Google Analytics",
        "MS=":            "Microsoft 365 / Office 365",
        "docusign":       "DocuSign (firma digital)",
        "atlassian":      "Atlassian (Jira/Confluence)",
        "stripe":         "Stripe (pagos)",
        "hubspot":        "HubSpot CRM",
        "salesforce":     "Salesforce CRM",
        "zendesk":        "Zendesk Support",
        "intercom":       "Intercom",
        "_dmarc":         "DMARC configurado",
    }

    detected_tech = []
    for txt in txt_records:
        for key, tech in tech_indicators.items():
            if key.lower() in txt.lower():
                detected_tech.append(tech)
                ok(f"  Tecnología detectada via TXT: {tech}")

    if detected_tech:
        add_finding(
            "Stack tecnológico identificado via DNS TXT",
            f"Tecnologías detectadas: {', '.join(set(detected_tech))}",
            "INFO",
            "DNS/TXT Records",
            "\n".join(txt_records[:10])
        )

    # Verificar si DMARC está configurado (si no, riesgo de spoofing)
    r_dmarc = get(
        "https://dns.google/resolve",
        params={"name": f"_dmarc.{domain}", "type": "TXT"}
    )
    if r_dmarc:
        try:
            dmarc_data = r_dmarc.json().get("Answer", [])
            if not dmarc_data:
                warn("DMARC no configurado — el dominio es vulnerable a email spoofing")
                add_finding(
                    "DMARC no configurado",
                    "El dominio no tiene registro DMARC. Atacantes pueden suplantar "
                    "emails corporativos (phishing/BEC).",
                    "HIGH",
                    "DNS",
                )
            else:
                ok(f"DMARC encontrado: {dmarc_data[0]['data'][:80]}")
        except Exception:
            pass

    REPORT["dns_records"] = results
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — Email Harvesting (Hunter.io)
# ═══════════════════════════════════════════════════════════════════════════════

def harvest_emails():
    banner("MÓDULO  — Email Harvesting via Hunter.io")
    domain = CONFIG["target_domain"]
    emails = []

    if not CONFIG["hunter_key"]:
        warn("HUNTER_KEY no configurado — usando búsqueda pública alternativa")
        # Búsqueda pública via Wayback CDX
        info("Buscando emails en texto archivado (Wayback CDX)...")
        r = get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "limit": "200",
                "filter": "mimetype:text/html",
            }
        )
        if r:
            try:
                urls = r.json()
                email_pattern = re.compile(
                    r'[a-zA-Z0-9._%+\-]+@' + re.escape(domain),
                    re.IGNORECASE
                )
                # Solo reportar los patrones encontrados en URLs
                found_in_urls = set()
                for item in urls:
                    url_str = str(item)
                    matches = email_pattern.findall(url_str)
                    found_in_urls.update(matches)
                if found_in_urls:
                    emails = [{"email": e, "source": "wayback"} for e in found_in_urls]
                    ok(f"Emails encontrados en Wayback: {list(found_in_urls)}")
            except Exception:
                pass
        REPORT["emails"] = emails
        return emails

    # Hunter.io API
    info(f"Consultando Hunter.io para @{domain}")
    r = get(
        "https://api.hunter.io/v2/domain-search",
        params={
            "domain": domain,
            "api_key": CONFIG["hunter_key"]
        }
    )
    if r and r.status_code == 200:
        data = r.json().get("data", {})
        print(data)
        raw_emails = data.get("emails", [])
        pattern = data.get("pattern", "unknown")
        ok(f"Patrón de email corporativo: {pattern}@{domain}")

        for e in raw_emails:
            entry = {
                "email": e.get("value"),
                "first_name": e.get("first_name"),
                "last_name": e.get("last_name"),
                "position": e.get("position"),
                "confidence": e.get("confidence"),
                "sources": [s.get("uri") for s in e.get("sources", [])[:3]],
            }
            emails.append(entry)
            ok(f"  {entry['email']} — {entry['position']} (conf: {entry['confidence']}%)")

        if emails:
            add_finding(
                f"{len(emails)} emails corporativos expuestos públicamente",
                f"Patrón: {pattern}@{domain}. Los emails pueden usarse para "
                "phishing, password spraying o enumeración de empleados.",
                "MEDIUM",
                "Hunter.io",
                "\n".join([e["email"] for e in emails[:20]])
            )

    REPORT["emails"] = emails
    return emails


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — Wayback Machine (Endpoints y Rutas Históricas)
# ═══════════════════════════════════════════════════════════════════════════════

def wayback_recon():
    banner("MÓDULO  — Wayback Machine — Endpoints y Rutas Históricas")
    domain = CONFIG["target_domain"]
    endpoints = []
    interesting = []

    # CDX API — todas las URLs indexadas
    info("Consultando Wayback CDX API...")
    r = get(
        "http://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,statuscode,mimetype,timestamp",
            "limit": "500",
            "collapse": "urlkey",
        }
    )
    if not r:
        return []

    try:
        rows = r.json()
    except Exception:
        return []

    # Patrones de interés para Shadow IT
    interesting_patterns = {
        r"/admin":           "Panel de administración",
        r"/wp-admin":        "WordPress admin",
        r"/wp-login":        "WordPress login",
        r"/phpmyadmin":      "phpMyAdmin expuesto",
        r"/api/":            "Endpoint de API",
        r"\.env":            "Archivo .env (credenciales)",
        r"\.git":            "Repositorio Git expuesto",
        r"backup":           "Archivo de backup",
        r"config":           "Archivo de configuración",
        r"\.sql":            "Dump de base de datos",
        r"\.xlsx|\.csv":     "Datos en hoja de cálculo",
        r"login|signin":     "Página de login",
        r"staging|dev|test": "Entorno no productivo",
        r"internal|intra":   "Sistema interno expuesto",
        r"swagger|api-docs": "Documentación de API expuesta",
        r"jenkins|gitlab":   "CI/CD expuesto",
        r"kibana|grafana":   "Dashboard de monitoreo expuesto",
    }

    seen = set()
    for row in rows[1:]:  # primera fila son headers
        if len(row) < 2:
            continue
        url, status = row[0], row[1]
        if url in seen:
            continue
        seen.add(url)
        endpoints.append({"url": url, "status": status})

        for pattern, label in interesting_patterns.items():
            if re.search(pattern, url, re.IGNORECASE):
                interesting.append({"url": url, "type": label, "status": status})
                warn(f"  INTERESANTE [{label}]: {url}")
                break

    ok(f"Total URLs archivadas: {len(endpoints)}")
    ok(f"URLs de interés: {len(interesting)}")

    if interesting:
        shadow_it = [i for i in interesting if any(
            kw in i["type"].lower() for kw in
            ["staging", "dev", "test", "interno", "backup", "env", "git"]
        )]
        if shadow_it:
            REPORT["shadow_it"].extend(shadow_it)
            add_finding(
                f"{len(shadow_it)} recursos Shadow IT detectados en archivo histórico",
                "URLs de entornos no productivos, paneles admin o archivos sensibles "
                "encontrados en Wayback Machine.",
                "HIGH",
                "Wayback Machine CDX",
                "\n".join([i["url"] for i in shadow_it[:15]])
            )

    REPORT["wayback_endpoints"] = interesting
    return interesting

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — Cloud Storage (S3, GCS, Azure Blob)
# ═══════════════════════════════════════════════════════════════════════════════

def check_cloud_storage():
    banner("MÓDULO  — Cloud Storage — Buckets y Blobs Expuestos")
    exposed = []

    for variant in CONFIG["bucket_variants"]:
        targets = [
            # AWS S3
            {"url": f"https://{variant}.s3.amazonaws.com", "provider": "AWS S3"},
            {"url": f"https://s3.amazonaws.com/{variant}", "provider": "AWS S3 (path)"},
            # Google Cloud Storage
            {"url": f"https://{variant}.storage.googleapis.com", "provider": "GCS"},
            {"url": f"https://storage.googleapis.com/{variant}", "provider": "GCS (path)"},
            # Azure Blob
            {"url": f"https://{variant}.blob.core.windows.net", "provider": "Azure Blob"},
        ]

        for t in targets:
            r = get(t["url"])
            if not r:
                continue

            if r.status_code == 200:
                size = len(r.content)
                ok(f"  EXPUESTO PÚBLICAMENTE: [{t['provider']}] {t['url']}")
                exposed.append({
                    "url": t["url"],
                    "provider": t["provider"],
                    "status": "PUBLIC",
                    "response_size": size,
                })
                add_finding(
                    f"Bucket cloud PÚBLICO: {t['url']}",
                    f"El bucket en {t['provider']} es accesible públicamente. "
                    "Puede contener datos sensibles, backups o configuraciones.",
                    "CRITICAL",
                    t["provider"],
                    f"URL: {t['url']}\nStatus: 200 OK\nSize: {size} bytes"
                )

            elif r.status_code == 403:
                warn(f"  Bucket EXISTE (privado): [{t['provider']}] {t['url']}")
                exposed.append({
                    "url": t["url"],
                    "provider": t["provider"],
                    "status": "EXISTS_PRIVATE",
                })
                add_finding(
                    f"Bucket cloud identificado (privado): {variant}",
                    f"El bucket existe en {t['provider']} pero es privado. "
                    "Confirma que pertenece a la organización y está bien configurado.",
                    "MEDIUM",
                    t["provider"],
                    t["url"]
                )

            elif r.status_code == 301 or r.status_code == 307:
                info(f"  Redirect detectado: {t['url']} → {r.headers.get('Location','')}")

    info(f"Revisados {len(CONFIG['bucket_variants'])} variantes × 5 providers = "
         f"{len(CONFIG['bucket_variants'])*5} URLs")
    ok(f"Buckets expuestos: {len([e for e in exposed if e['status']=='PUBLIC'])}")
    ok(f"Buckets identificados (privados): {len([e for e in exposed if 'PRIVATE' in e.get('status','')])} ")

    REPORT["exposed_buckets"] = exposed
    return exposed


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — GitHub Dorks (Secretos y Credenciales en Código)
# ═══════════════════════════════════════════════════════════════════════════════

def github_dorks():
    banner("MÓDULO  — GitHub — Búsqueda de Secretos y Código Expuesto")
    org = CONFIG["target_org"]
    findings = []

    dorks = [
        f'"{org}" password',
        f'"{org}" api_key',
        f'"{org}" secret_key',
        f'"{org}" aws_access_key',
        f'"{org}" database_url',
        f'"{org}" private_key',
        f'"{org}" token',
        f'"{CONFIG["target_domain"]}" password',
        f'"{CONFIG["target_domain"]}" config',
        f'"{CONFIG["target_domain"]}" .env',
        f'"{CONFIG["target_domain"]}" credentials',
    ]

    # GitHub Search API — con token (30 req/min) o sin token (10 req/min)
    gh_headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "OSINT-SecurityAudit",
    }
    if CONFIG["github_token"]:
        gh_headers["Authorization"] = f"token {CONFIG['github_token']}"
        info("GitHub Search API autenticada via .env (GITHUB_TOKEN) — 30 req/min")
    else:
        info("GitHub Search API sin token (GITHUB_TOKEN no en .env) — 10 req/min")

    for dork in dorks:
        r = get(
            "https://api.github.com/search/code",
            params={"q": dork, "per_page": 5},
            headers=gh_headers,
        )
        if not r:
            continue

        if r.status_code == 403:
            warn("GitHub rate limit alcanzado — esperando 60s...")
            time.sleep(60)
            continue

        if r.status_code == 422:
            continue  # Query no válida

        try:
            data = r.json()
            total = data.get("total_count", 0)
            items = data.get("items", [])

            if total > 0:
                warn(f"  [{total} resultados] Dork: {dork}")
                for item in items:
                    finding = {
                        "dork": dork,
                        "total_count": total,
                        "repo": item.get("repository", {}).get("full_name"),
                        "file": item.get("name"),
                        "url": item.get("html_url"),
                        "sha": item.get("sha"),
                    }
                    findings.append(finding)
                    ok(f"    Repo: {finding['repo']} | Archivo: {finding['file']}")
        except Exception:
            pass

    if findings:
        repos = list(set([f["repo"] for f in findings if f.get("repo")]))
        add_finding(
            f"Código relacionado con la organización en GitHub ({len(findings)} resultados)",
            f"Se encontraron {len(findings)} archivos en {len(repos)} repositorios. "
            "Revisar si contienen credenciales, configs o datos sensibles.",
            "HIGH",
            "GitHub Search API",
            "\n".join([f["url"] for f in findings[:10] if f.get("url")])
        )

    # URLs para revisión manual (GitHub no permite scraping de contenido sin auth)
    info("\nURLs de búsqueda manual recomendadas (abrir en navegador):")
    manual_dorks = [
        f"https://github.com/search?q={org}+password&type=code",
        f"https://github.com/search?q={org}+api_key&type=code",
        f"https://github.com/search?q={CONFIG['target_domain']}&type=code",
        f"https://github.com/search?q=%22{CONFIG['target_domain']}%22+.env&type=code",
    ]
    for url in manual_dorks:
        info(f"  {url}")

    REPORT["github_findings"] = findings
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — VirusTotal (Relaciones de Dominio)
# ═══════════════════════════════════════════════════════════════════════════════

def virustotal_recon():
    banner("MÓDULO  — VirusTotal — Relaciones de Dominio e IPs")
    domain = CONFIG["target_domain"]
    results = {}

    # VirusTotal API pública (sin key) — consulta de dominio
    info(f"Consultando VirusTotal para {domain}")

    # Endpoint público (sin API key, info limitada)
    r = get(f"https://www.virustotal.com/vtapi/v2/domain/report",
            params={"domain": domain, "apikey": "public"})

    # Alternativa: usar la API v3 pública (sin key para info básica)
    vt_key = CONFIG["virustotal_key"] or "public"
    if CONFIG["virustotal_key"]:
        info("VirusTotal autenticado via .env (VIRUSTOTAL_KEY)")
    else:
        info("VirusTotal sin key (VIRUSTOTAL_KEY no en .env) — info básica solamente")
    r2 = get(f"https://www.virustotal.com/api/v3/domains/{domain}",
             headers={"x-apikey": vt_key})

    if r2 and r2.status_code == 200:
        try:
            data = r2.json()
            attrs = data.get("data", {}).get("attributes", {})
            results = {
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "last_update": attrs.get("last_update_date"),
                "tags": attrs.get("tags", []),
            }
            ok(f"Reputación VT: {results['reputation']}")
            ok(f"Registrar: {results['registrar']}")
            if results["categories"]:
                ok(f"Categorías: {results['categories']}")
            stats = results.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                add_finding(
                    f"Dominio marcado como malicioso en {malicious} motores AV",
                    "El dominio tiene detecciones en VirusTotal.",
                    "CRITICAL",
                    "VirusTotal",
                    json.dumps(stats)
                )
        except Exception as e:
            err(f"Error parseando VT: {e}")
    else:
        info("VirusTotal requiere API key para consultas completas")
        info("Registra gratis en: https://www.virustotal.com/gui/join-us")

    REPORT["virustotal"] = results
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — HuggingFace NER (Extracción de Entidades con IA)
# ═══════════════════════════════════════════════════════════════════════════════

def ai_ner_extraction():
    banner("MÓDULO  — HuggingFace NER — Extracción de Entidades con IA")

    # Construir corpus de texto OSINT recolectado
    corpus_parts = []

    # Agregar emails como texto
    for email_entry in REPORT["emails"]:
        if isinstance(email_entry, dict):
            parts = [
                email_entry.get("email", ""),
                email_entry.get("first_name", ""),
                email_entry.get("last_name", ""),
                email_entry.get("position", ""),
            ]
            corpus_parts.append(" ".join(filter(None, parts)))

    # Agregar DNS TXT records
    for record in REPORT["dns_records"].get("TXT", []):
        corpus_parts.append(record)

    # Agregar findings
    for f in REPORT["findings"]:
        corpus_parts.append(f"{f['title']}. {f['description']}")

    if not corpus_parts:
        corpus_parts = [
            f"{CONFIG['target_org']} ({CONFIG['target_domain']}) is the target organization "
            f"under OSINT analysis. Slug: {CONFIG['target_slug']}."
        ]

    corpus = " ".join(corpus_parts)[:1000]  # límite de tokens del modelo

    info(f"Procesando {len(corpus)} caracteres de texto OSINT con bert-base-NER...")

    result = hf_inference(
        "dslim/bert-base-NER",
        {"inputs": corpus}
    )

    if not result or isinstance(result, dict) and "error" in result:
        warn("NER no disponible (verifica HF_TOKEN)")
        return {}

    # Agrupar por tipo de entidad
    entities = defaultdict(set)
    if isinstance(result, list):
        for ent in result:
            if isinstance(ent, dict):
                label = ent.get("entity_group", ent.get("entity", "MISC"))
                word = ent.get("word", "").replace("##", "")
                if word and len(word) > 2:
                    entities[label].add(word)

    entity_map = {
        "PER": "Personas",
        "ORG": "Organizaciones",
        "LOC": "Ubicaciones",
        "MISC": "Miscelánea",
    }

    for label, words in entities.items():
        display = entity_map.get(label, label)
        ok(f"  {display}: {', '.join(list(words)[:8])}")
        REPORT["entities"][display] = list(words)

    if entities.get("PER"):
        add_finding(
            f"Personas identificadas via NER en datos OSINT",
            f"El modelo NER identificó personas: {', '.join(list(entities['PER'])[:10])}",
            "INFO",
            "HuggingFace / bert-base-NER",
        )

    return dict(entities)


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — HuggingFace Zero-Shot Classification (Clasificación de Riesgos)
# ═══════════════════════════════════════════════════════════════════════════════

def ai_risk_classification():
    banner("MÓDULO  — HuggingFace — Clasificación Zero-Shot de Riesgos")

    candidate_labels = [
        "credential leak",
        "sensitive financial data",
        "personal information",
        "infrastructure information",
        "shadow IT",
        "public exposure",
        "low risk information",
    ]

    classified = []
    texts_to_classify = [f["description"] for f in REPORT["findings"]][:8]

    if not texts_to_classify:
        texts_to_classify = [
            f"Exposed subdomain pointing to {CONFIG['target_domain']}",
            f"Email addresses found for {CONFIG['target_org']} ({CONFIG['target_slug']}) employees",
        ]

    for text in texts_to_classify:
        info(f"Clasificando: {text[:60]}...")
        result = hf_inference(
            "facebook/bart-large-mnli",
            {
                "inputs": text,
                "parameters": {"candidate_labels": candidate_labels}
            }
        )

        if result and isinstance(result, dict) and "labels" in result:
            top_label = result["labels"][0]
            top_score = result["scores"][0]
            ok(f"  → {top_label} (confianza: {top_score:.2%})")
            classified.append({
                "text": text[:80],
                "top_category": top_label,
                "confidence": round(top_score, 3),
                "all_labels": list(zip(result["labels"][:3], [round(s,3) for s in result["scores"][:3]])),
            })
        else:
            warn("Clasificación no disponible para este texto")

    REPORT["risk_classifications"] = classified
    return classified


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — AI Correlation (Síntesis con Claude API)
# ═══════════════════════════════════════════════════════════════════════════════

def ai_correlation():
    banner("MÓDULO  — Síntesis IA — Correlación de Hallazgos")
    info("Usando Claude API para correlacionar y priorizar hallazgos...")

    # Preparar resumen de hallazgos para el LLM
    findings_summary = json.dumps({
        "target": CONFIG["target_org"],
        "subdomains_found": len(REPORT["subdomains"]),
        "emails_found": len(REPORT["emails"]),
        "exposed_buckets": len([b for b in REPORT["exposed_buckets"] if b.get("status") == "PUBLIC"]),
        "github_findings": len(REPORT["github_findings"]),
        "shadow_it_items": len(REPORT["shadow_it"]),
        "findings": REPORT["findings"][:10],
        "entities": dict(REPORT["entities"]),
        "dns_technologies": REPORT["dns_records"].get("TXT", [])[:5],
    }, indent=2)

    prompt = f"""Eres un analista senior de ciberseguridad y OSINT. 
Analiza los siguientes hallazgos de reconocimiento pasivo para la organización "{CONFIG['target_org']}" ({CONFIG['target_domain']}) 
y genera un análisis ejecutivo conciso en español que incluya:

1. Resumen de la superficie de ataque encontrada
2. Los 3 hallazgos más críticos y por qué
3. Patrones de Shadow IT detectados
4. Riesgos de correlación (cómo los hallazgos se relacionan entre sí)
5. Top 5 acciones de remediación inmediata

DATOS OSINT RECOLECTADOS:
{findings_summary}

Responde en formato estructurado, conciso y accionable. Máximo 400 palabras."""

    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"Content-Type": "application/json"},
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        if r.status_code == 200:
            content = r.json().get("content", [{}])[0].get("text", "")
            ok("Análisis IA generado exitosamente")
            print(f"\n{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")
            print(content)
            print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}\n")
            REPORT["ai_summary"] = content
            return content
        else:
            warn(f"Claude API status: {r.status_code}")
    except Exception as e:
        err(f"Error en Claude API: {e}")

    # Fallback: síntesis basada en reglas
    summary = f"""
## Síntesis OSINT — {CONFIG['target_org']} ({CONFIG['target_domain']})

**Superficie de ataque:**
- {len(REPORT['subdomains'])} subdominios activos identificados
- {len(REPORT['emails'])} emails corporativos expuestos
- {len(REPORT['exposed_buckets'])} recursos cloud identificados
- {len(REPORT['github_findings'])} menciones en repositorios públicos

**Hallazgos críticos:**
{chr(10).join([f"- [{f['risk']}] {f['title']}" for f in REPORT['findings'][:5]])}

**Shadow IT detectado:** {len(REPORT['shadow_it'])} elementos
"""
    REPORT["ai_summary"] = summary
    return summary


# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO  — Generación de Reporte Markdown
# ═══════════════════════════════════════════════════════════════════════════════

def generate_report():
    banner("MÓDULO  — Generación de Reporte Ejecutivo")

    now = datetime.datetime.now(datetime.timezone.utc)
    # Crear carpeta "reportes" si no existe
    reportes_dir = Path("reportes")
    reportes_dir.mkdir(exist_ok=True)
    report_path = reportes_dir / f"osint_report_{CONFIG['target_slug']}_{now.strftime('%Y%m%d_%H%M')}.md"

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        REPORT["findings"],
        key=lambda x: risk_order.get(x.get("risk", "INFO"), 5)
    )

    risk_counts = defaultdict(int)
    for f in REPORT["findings"]:
        risk_counts[f.get("risk", "INFO")] += 1

    md = f"""# OSINT Intelligence Report
## Objetivo: {CONFIG['target_org']} ({CONFIG['target_domain']})

| Campo | Valor |
|-------|-------|
| Fecha | {now.strftime('%Y-%m-%d %H:%M UTC')} |
| Metodología | Reconocimiento pasivo + semi-activo |
| Herramientas | crt.sh, Wayback Machine, Shodan, Hunter.io, HuggingFace AI |
| Clasificación | CONFIDENCIAL — Uso interno |

---

## Resumen Ejecutivo

{REPORT.get('ai_summary', 'Ver hallazgos detallados a continuación.')}

---

## Métricas de Superficie de Ataque

| Métrica | Valor |
|---------|-------|
| Subdominios activos | {len(REPORT['subdomains'])} |
| Emails corporativos expuestos | {len(REPORT['emails'])} |
| Recursos cloud identificados | {len(REPORT['exposed_buckets'])} |
| Findings en GitHub | {len(REPORT['github_findings'])} |
| Elementos Shadow IT | {len(REPORT['shadow_it'])} |
| **Hallazgos CRÍTICOS** | **{risk_counts.get('CRITICAL', 0)}** |
| Hallazgos ALTOS | {risk_counts.get('HIGH', 0)} |
| Hallazgos MEDIOS | {risk_counts.get('MEDIUM', 0)} |
| Hallazgos BAJOS/INFO | {risk_counts.get('LOW', 0) + risk_counts.get('INFO', 0)} |

---

## Hallazgos Detallados

"""

    for i, finding in enumerate(sorted_findings, 1):
        risk_emoji = {
            "CRITICAL": "🔴", "HIGH": "🟠",
            "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"
        }.get(finding.get("risk", "INFO"), "⚪")

        md += f"""### {i}. {risk_emoji} [{finding.get('risk','INFO')}] {finding['title']}

**Fuente:** {finding.get('source', 'N/A')}
**Descripción:** {finding['description']}

"""
        if finding.get("evidence"):
            evidence_preview = finding["evidence"][:300]
            md += f"**Evidencia:**\n```\n{evidence_preview}\n```\n\n"

        md += "---\n\n"

    # Subdominios
    md += "## Subdominios Activos\n\n"
    if REPORT["subdomains"]:
        md += "| Subdominio | IP |\n|-----------|----|\n"
        for s in REPORT["subdomains"][:30]:
            md += f"| `{s['subdomain']}` | `{s['ip']}` |\n"
    else:
        md += "_No se encontraron subdominios resolvibles._\n"

    # DNS
    md += "\n## Registros DNS\n\n"
    for rtype, values in REPORT["dns_records"].items():
        md += f"**{rtype}:** {', '.join(values[:5])}\n\n"

    # Emails
    md += "## Emails Corporativos Expuestos\n\n"
    if REPORT["emails"]:
        md += "| Email | Nombre | Cargo | Confianza |\n|-------|--------|-------|-----------|\n"
        for e in REPORT["emails"][:20]:
            if isinstance(e, dict):
                md += (f"| `{e.get('email','')}` | "
                       f"{e.get('first_name','')} {e.get('last_name','')} | "
                       f"{e.get('position','N/A')} | {e.get('confidence','?')}% |\n")
    else:
        md += "_No se encontraron emails._\n"

    # Entities IA
    md += "\n## Entidades Extraídas con IA (NER)\n\n"
    for category, items in REPORT["entities"].items():
        if items:
            md += f"**{category}:** {', '.join(list(items)[:10])}\n\n"

    # Shadow IT
    md += "## Shadow IT Detectado\n\n"
    if REPORT["shadow_it"]:
        for item in REPORT["shadow_it"][:15]:
            md += f"- `{item.get('url','N/A')}` — {item.get('type','')}\n"
    else:
        md += "_No se detectaron elementos de Shadow IT en este scan._\n"

    # Recomendaciones
    md += """
## Recomendaciones de Remediación

### Prioridad Inmediata (24-72h)
1. Revisar y eliminar buckets cloud sin uso o mal configurados
2. Rotar credenciales si se encontraron en repositorios GitHub
3. Habilitar DMARC si no está configurado (previene spoofing)
4. Auditar subdominios huérfanos para prevenir takeover

### Corto Plazo (7-30 días)
5. Inventariar todos los servicios SaaS en uso (eliminar Shadow IT)
6. Implementar monitoreo continuo de superficie de ataque
7. Revisar y limpiar metadata de documentos públicos (FOCA)
8. Configurar alertas en Have I Been Pwned para el dominio corporativo

### Mediano Plazo (30-90 días)
9. Implementar programa de gestión de activos digitales
10. Capacitar empleados sobre exposición de datos en LinkedIn/GitHub

---

## Metodología

Este reporte fue generado mediante reconocimiento **exclusivamente pasivo y semi-activo**.
No se realizó ningún ataque, exploit ni acceso no autorizado.
Todas las fuentes consultadas son públicas y legalmente accesibles.

**Herramientas:** crt.sh · Wayback Machine · Shodan InternetDB · Hunter.io ·
GitHub Search · VirusTotal · HuggingFace (bert-base-NER, bart-large-mnli) ·
Google DNS-over-HTTPS · Claude API

*Reporte generado automáticamente por OSINT-Pipeline v1.0*
"""

    report_path.write_text(md, encoding="utf-8")
    ok(f"Reporte guardado: {report_path}")

    # También guardar JSON crudo
    json_path = report_path.with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(REPORT, f, indent=2, ensure_ascii=False, default=str)
    ok(f"Datos JSON guardados: {json_path}")

    return str(report_path)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN — Orquestador del Pipeline
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║        OSINT CON ESTEROIDES — Pipeline IA Automatizado              ║
║        Objetivo: {CONFIG['target_org']:<38}         ║
║        Dominio:  {CONFIG['target_domain']:<38}         ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

    # Verificar configuración
    if not CONFIG["hf_token"]:
        warn("HF_TOKEN no configurado — módulos IA deshabilitados")
        warn("Configura: export HF_TOKEN=hf_tu_token_aqui")
        warn("Token gratis en: https://huggingface.co/settings/tokens")

    start = time.time()

    # ─── Ejecutar pipeline ───────────────────────────────────────────────────

    try:
        dns_recon()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        harvest_emails()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        wayback_recon()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        check_cloud_storage()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        github_dorks()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        virustotal_recon()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        ai_ner_extraction()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        ai_risk_classification()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        ai_correlation()
    except Exception as e:
        err(f"Módulo  falló: {e}")

    try:
        report_path = generate_report()
    except Exception as e:
        err(f"Módulo  falló: {e}")
        report_path = "N/A"

    # ─── Resumen final ───────────────────────────────────────────────────────
    elapsed = time.time() - start
    banner("PIPELINE COMPLETO")
    ok(f"Tiempo total: {elapsed:.1f}s")
    ok(f"Hallazgos totales: {len(REPORT['findings'])}")
    ok(f"Reporte: {report_path}")

    risk_counts = defaultdict(int)
    for f in REPORT["findings"]:
        risk_counts[f.get("risk", "INFO")] += 1

    print(f"""
  {Fore.RED}CRÍTICOS: {risk_counts['CRITICAL']}{Style.RESET_ALL}  |  \
{Fore.YELLOW}ALTOS: {risk_counts['HIGH']}{Style.RESET_ALL}  |  \
{Fore.BLUE}MEDIOS: {risk_counts['MEDIUM']}{Style.RESET_ALL}  |  \
{Fore.GREEN}BAJOS: {risk_counts['LOW'] + risk_counts['INFO']}{Style.RESET_ALL}
""")


if __name__ == "__main__":
    main()
