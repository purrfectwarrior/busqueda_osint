Arquitectura del pipeline
Capa 1 — Reconocimiento pasivo (sin tocar al objetivo)
Usas crt.sh, DNSdumpster, Wayback Machine y VirusTotal para mapear la superficie sin generar logs en los servidores del objetivo. El tab Reconocimiento cubre esto con 12 herramientas gratuitas.
Capa 2 — Shadow IT (el tab más crítico)
Los vectores de mayor riesgo son:

Subdomain takeover: subdominios apuntando a Heroku/S3 cancelados que un atacante puede reclamar
Buckets S3 públicos: el script en el tab Scripts ya tiene el enumerador listo
GitHub leaks: credenciales hardcodeadas en repos públicos de empleados

Capa 3 — IA con HuggingFace
El pipeline usa 3 modelos encadenados:

bert-base-NER → extrae entidades (personas, tecnologías, orgs) de todo el texto OSINT recolectado
bart-large-mnli → clasifica zero-shot si un hallazgo contiene datos sensibles
sentence-transformers → agrupa hallazgos similares semánticamente para el reporte final
