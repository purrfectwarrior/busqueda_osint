# 🔍 OSINT Pipeline con IA

**Recolección automatizada de inteligencia de código abierto + análisis inteligente con HuggingFace**

Una herramienta para investigadores de seguridad, auditores y defensores que quieran mapear la **superficie de ataque digital** de una organización usando solo técnicas **legales y pasivas**.

---

## 📋 ¿Qué hace?

Este script ejecuta un **análisis OSINT completo** en 12 módulos:

| # | Módulo | ¿Qué busca? | Fuente |
|---|--------|-----------|--------|
| 1 | DNS Recon | Registros A, MX, TXT, NS | Google DNS |
| 2 | Email Harvesting | Empleados corporativos expuestos | Hunter.io API |
| 3 | Wayback Machine | URLs antiguas, APIs expuestas, .env files | Web Archive CDX |
| 4 | Cloud Storage | Buckets S3, GCS, Azure accesibles | AWS, Google Cloud, Azure |
| 5 | GitHub Dorks | Credenciales en repos públicos | GitHub API |
| 6 | VirusTotal | Reputación del dominio, CVEs | VirusTotal API |
| 7 | Análisis IA (NER) | Personas, tecnologías, ubicaciones | HuggingFace BERT |
| 8 | Clasificación IA | Riesgo: "credential leak", "shadow IT", etc. | HuggingFace BART |
| 9 | Síntesis IA | Análisis cruzado de hallazgos | Claude API |
| 10 | Shadow IT | Entornos dev/staging no productivos | Todos los anteriores |
| 11 | Reporte Final | Markdown + JSON con hallazgos | Generado localmente |

---

## ⚡ Quick Start (2 minutos)

### 1. Instalar dependencias
```bash
pip install requests beautifulsoup4 dnspython colorama tqdm python-dotenv
```

### 2. Configurar API keys
Copia y configura el archivo `.env`:
```bash
cp env.example .env
# Edita .env y rellena las keys que tengas
```

Mínimo obligatorio:
```env
target_domain=tudominio.com
```

Opcional (para más datos):
```env
HF_TOKEN=hf_xxxxx                    # HuggingFace (IA) → huggingface.co/settings/tokens
HUNTER_KEY=xxxxx                     # Email harvesting → hunter.io/api-keys
SHODAN_KEY=xxxxx                     # Infraestructura → shodan.io/account
VIRUSTOTAL_KEY=xxxxx                 # Reputación → virustotal.com/gui/my-apikey
GITHUB_TOKEN=github_pat_xxxxx        # Búsqueda de código → github.com/settings/tokens
```

### 3. Ejecutar
```bash
python busqueda_osint.py
```

El script generará un reporte en:
```
reportes/osint_report_DOMINIO_FECHA.md
reportes/osint_report_DOMINIO_FECHA.json
```

---

## 📊 Ejemplo de salida

```
[+]  IP: 203.0.113.45
[+]  Puertos abiertos: [80, 443, 8080]
[!]  CVEs detectados: ['CVE-2021-44228']

[+]  Patrón de email corporativo: firstname.lastname@empresa.com
[+]    john.smith@empresa.com — Senior Manager (conf: 98%)

[+]  EXPUESTO PÚBLICAMENTE: [AWS S3] https://empresa-docs.s3.amazonaws.com
[-]  Panel de administración: https://web.archive.org/web/*/ejemplo.com/admin

...

CRÍTICOS: 2  |  ALTOS: 5  |  MEDIOS: 8  |  BAJOS: 12
```

---

## 🏗️ Estructura de carpetas

```
busqueda_osint/
├── busqueda_osint.py          # Script principal
├── osint_pipeline_*.py         # Alternativas (con Shodan, etc.)
├── env.example                 # Plantilla de configuración
├── .env                        # Tu archivo de secrets (NO subir a git)
├── README.md                   # Este archivo
├── reportes/                   # 📁 Aquí se guardan los resultados
│   ├── osint_report_empresa_20260422_1523.md
│   └── osint_report_empresa_20260422_1523.json
└── osint_run.log              # Log de ejecución
```

---

## 🧠 Cómo funciona la IA

### Extracción de Entidades (NER)
- **Modelo:** `dslim/bert-base-NER`
- **Entrada:** Todo el texto OSINT recolectado
- **Salida:** Personas, organizaciones, ubicaciones
- **Uso:** Mapear estructura corporativa

### Clasificación de Riesgos (Zero-Shot)
- **Modelo:** `facebook/bart-large-mnli`
- **Entrada:** Cada hallazgo
- **Salida:** Categoría de riesgo + confianza
- **Uso:** Priorizar los hallazgos más críticos

### Síntesis Inteligente
- **Modelo:** Claude API (Anthropic)
- **Entrada:** Resumen de todos los hallazgos
- **Salida:** Análisis ejecutivo con recomendaciones
- **Uso:** Reporte final legible

---

## ⚖️ Consideraciones Legales

✅ **Legal** — Todo el script usa:
- Fuentes públicas (Wayback, GitHub, DNS públicos)
- APIs gratuitas o de pago (con tu permiso)
- Técnicas **100% pasivas** (sin escaneo de puertos real, sin explotación)

❌ **No legal** — No hagas esto:
- Acceder a sistemas sin autorización
- Usar datos para malware o phishing
- Usar en objetivos sin permiso escrito

💡 **Mejor práctica:**
- Usa solo en dominios que controles o tengas permiso
- Guarda el reporte de forma segura
- Usa los hallazgos para mejorar seguridad

---

## 🔑 Configuración API Keys

### Gratis pero requiere registro
- **Hunter.io** — 50 búsquedas/mes gratis → [hunter.io](https://hunter.io)
- **Shodan** — 1 búsqueda/mes gratis → [shodan.io](https://shodan.io)
- **VirusTotal** — 500 búsquedas/día gratis → [virustotal.com](https://www.virustotal.com)
- **HuggingFace** — Token gratuito → [huggingface.co](https://huggingface.co/settings/tokens)
- **GitHub** — PAT gratuito → [github.com/settings/tokens](https://github.com/settings/tokens)

### Completamente gratis (sin key)
- Wayback Machine (Archive.org)
- Google DNS-over-HTTPS
- Shodan InternetDB (sin filtros avanzados)

---

## 🛠️ Troubleshooting

### Error: "target_domain no está definido"
```
Solución: Edita .env y agrega:
target_domain=tudominio.com
```

### Error 403 en Shodan
```
Solución: Tu API key está expirada o sin créditos.
El script usa Shodan InternetDB gratis como fallback.
```

### Error "HuggingFace token no válido"
```
Solución: 
1. Verifica el token en .env
2. Crea uno nuevo en: https://huggingface.co/settings/tokens
3. Recarga el script
```

### Ejecución lenta
```
Razón: Rate limiting de las APIs (esperado).
El script duerme entre requests para ser respetuoso.
Usa -h o --help si está implementado.
```

---

## 📈 Salida esperada

Un reporte completo incluye:

✅ **Tabla resumen** — Cuántos subdominios, emails, buckets encontrados  
✅ **Hallazgos priorizados** — Críticos, Altos, Medios, Bajos  
✅ **Subdominios activos** — IPs y estado DNS  
✅ **Registros DNS** — A, MX, TXT, NS (tecnologías detectadas)  
✅ **Emails corporativos** — Nombres, posiciones, confianza  
✅ **Shadow IT** — Entornos dev/staging expuestos  
✅ **CVEs e infraestructura** — Puertos, servicios, vulnerabilidades  
✅ **Análisis IA** — Personas, organizaciones detectadas  
✅ **Recomendaciones** — Top 10 acciones de remediación  

---

## 🤝 Contribuciones

¿Encontraste un bug o quieres agregar una fuente OSINT? ¡Abre un issue!

---

## ⚠️ Disclaimer

Este código es **educativo**. El usuario es responsable de:
- Respetar leyes locales y privacidad
- Tener permiso para auditar el objetivo
- Mantener secretos (no compartir reportes)
- Cumplir con regulaciones (GDPR, CCPA, etc.)

**Uso responsable = OSINT; Uso irresponsable = ilegal**

---

*Última actualización: Abril 2026 | v1.0*
