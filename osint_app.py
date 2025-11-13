import streamlit as st
import socket
import ssl
import whois
import requests
import pandas as pd
import dns.resolver
import sqlite3
import json
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import io

st.set_page_config(
    page_title="OSINT Domain Recon Pro",
    layout="wide",
    page_icon="🔍",
    initial_sidebar_state="expanded"
)

# ===== FUNCIONES DE BASE DE DATOS =====
def init_database():
    """Inicializa la base de datos SQLite"""
    conn = sqlite3.connect('osint_scans.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  domain TEXT NOT NULL,
                  scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  data TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def save_scan(domain, data):
    """Guarda un escaneo en la base de datos"""
    conn = sqlite3.connect('osint_scans.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (domain, data) VALUES (?, ?)",
              (domain, json.dumps(data)))
    conn.commit()
    scan_id = c.lastrowid
    conn.close()
    return scan_id

def get_scan_history(domain, limit=10):
    """Obtiene el historial de escaneos de un dominio"""
    conn = sqlite3.connect('osint_scans.db')
    c = conn.cursor()
    c.execute("""SELECT id, scan_date, data FROM scans
                 WHERE domain = ?
                 ORDER BY scan_date DESC
                 LIMIT ?""", (domain, limit))
    results = c.fetchall()
    conn.close()
    return results

# ===== FUNCIONES DE ANÁLISIS DNS =====
def get_dns_records(domain):
    """Obtiene todos los registros DNS del dominio"""
    dns_data = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    # Configurar DNS resolvers públicos como fallback
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    except:
        # Si falla, intentar con configuración del sistema
        try:
            resolver = dns.resolver.Resolver()
        except:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8']

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            records = []
            for rdata in answers:
                if record_type == 'MX':
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == 'SOA':
                    records.append(f"MNAME: {rdata.mname}, RNAME: {rdata.rname}")
                else:
                    records.append(str(rdata))
            dns_data[record_type] = records
        except dns.resolver.NoAnswer:
            dns_data[record_type] = []
        except dns.resolver.NXDOMAIN:
            dns_data[record_type] = ["Dominio no existe"]
        except Exception as e:
            dns_data[record_type] = [f"Error: {str(e)}"]

    return dns_data

# ===== FUNCIONES DE ANÁLISIS HTTP =====
def get_http_headers(domain):
    """Obtiene headers HTTP y analiza security headers"""
    http_data = {
        'headers': {},
        'security_headers': {},
        'redirect_chain': [],
        'status_code': None
    }

    try:
        # Intentar HTTPS primero
        url = f"https://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        http_data['status_code'] = response.status_code
        http_data['headers'] = dict(response.headers)

        # Analizar redirect chain
        if response.history:
            for resp in response.history:
                http_data['redirect_chain'].append({
                    'url': resp.url,
                    'status': resp.status_code
                })
            http_data['redirect_chain'].append({
                'url': response.url,
                'status': response.status_code
            })

        # Security headers importantes
        security_checks = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'No configurado ❌'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'No configurado ❌'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'No configurado ❌'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'No configurado ❌'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'No configurado ❌'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'No configurado ❌'),
            'Permissions-Policy': response.headers.get('Permissions-Policy', 'No configurado ❌')
        }
        http_data['security_headers'] = security_checks

    except requests.exceptions.SSLError:
        # Si HTTPS falla, intentar HTTP
        try:
            url = f"http://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=True)
            http_data['status_code'] = response.status_code
            http_data['headers'] = dict(response.headers)
            http_data['security_headers'] = {'Advertencia': 'Sitio sin HTTPS ⚠️'}
        except Exception as e:
            http_data['error'] = str(e)
    except Exception as e:
        http_data['error'] = str(e)

    return http_data

def detect_technologies(headers, html_content=None):
    """Detecta tecnologías basándose en headers y contenido"""
    technologies = []

    # Detección por headers
    server = headers.get('Server', '')
    if 'nginx' in server.lower():
        technologies.append('Nginx')
    if 'apache' in server.lower():
        technologies.append('Apache')
    if 'cloudflare' in server.lower():
        technologies.append('Cloudflare')

    x_powered = headers.get('X-Powered-By', '')
    if 'PHP' in x_powered:
        technologies.append(f'PHP {x_powered}')
    if 'ASP.NET' in x_powered:
        technologies.append('ASP.NET')

    # Cookies pueden revelar tecnologías
    set_cookie = headers.get('Set-Cookie', '')
    if 'wordpress' in set_cookie.lower():
        technologies.append('WordPress')
    if 'PHPSESSID' in set_cookie:
        technologies.append('PHP')

    return technologies if technologies else ['No detectadas']

# ===== FUNCIONES DE EXPORTACIÓN =====
def generate_markdown_report(domain, data):
    """Genera un reporte completo en Markdown"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = f"""# 🔍 Reporte OSINT Profesional
**Dominio:** `{domain}`
**Fecha:** {timestamp}
**Generado por:** OSINT Domain Recon Pro

---

## 📊 Resumen Ejecutivo

- **IP Principal:** {data.get('ip', 'N/A')}
- **Subdominios Encontrados:** {len(data.get('subdomains', []))}
- **Registros DNS:** {len([k for k, v in data.get('dns', {}).items() if v])}
- **Status HTTP:** {data.get('http', {}).get('status_code', 'N/A')}

---

"""

    # DNS Records
    if 'dns' in data:
        md += "## 🌐 Registros DNS\n\n"
        for record_type, records in data['dns'].items():
            if records:
                md += f"### {record_type}\n"
                for record in records:
                    md += f"- `{record}`\n"
                md += "\n"

    # HTTP Headers
    if 'http' in data:
        md += "## 🔒 Análisis HTTP\n\n"
        md += f"**Status Code:** {data['http'].get('status_code', 'N/A')}\n\n"

        if 'security_headers' in data['http']:
            md += "### Security Headers\n\n"
            for header, value in data['http']['security_headers'].items():
                status = "✅" if "No configurado" not in str(value) else "❌"
                md += f"{status} **{header}:** `{value}`\n\n"

        if data['http'].get('redirect_chain'):
            md += "### Redirect Chain\n\n"
            for i, redirect in enumerate(data['http']['redirect_chain'], 1):
                md += f"{i}. {redirect['url']} ({redirect['status']})\n"
            md += "\n"

    # WHOIS
    if 'whois' in data:
        md += "## 📋 Información WHOIS\n\n```json\n"
        md += json.dumps(data['whois'], indent=2)
        md += "\n```\n\n"

    # GeoIP
    if 'geoip' in data:
        md += "## 🌍 GeoIP\n\n"
        md += f"- **País:** {data['geoip'].get('country', 'N/A')}\n"
        md += f"- **Región:** {data['geoip'].get('region', 'N/A')}\n"
        md += f"- **Ciudad:** {data['geoip'].get('city', 'N/A')}\n"
        md += f"- **ISP:** {data['geoip'].get('org', 'N/A')}\n\n"

    # SSL
    if 'ssl' in data:
        md += "## 🔐 Certificado SSL\n\n"
        md += f"- **Emitido a:** {data['ssl'].get('Emitido a', 'N/A')}\n"
        md += f"- **Emitido por:** {data['ssl'].get('Emitido por', 'N/A')}\n"
        md += f"- **Válido desde:** {data['ssl'].get('Válido desde', 'N/A')}\n"
        md += f"- **Válido hasta:** {data['ssl'].get('Válido hasta', 'N/A')}\n\n"

        if 'SANs' in data['ssl'] and data['ssl']['SANs']:
            md += "### Subject Alternative Names\n\n"
            for san in data['ssl']['SANs']:
                md += f"- `{san}`\n"
            md += "\n"

    # Subdomains
    if 'subdomains' in data and data['subdomains']:
        md += f"## 🧬 Subdominios ({len(data['subdomains'])})\n\n"
        for subdomain in data['subdomains']:
            md += f"- `{subdomain}`\n"
        md += "\n"

    md += "\n---\n*Reporte generado automáticamente por OSINT Domain Recon Pro*\n"

    return md

def generate_pdf_report(domain, data):
    """Genera un reporte PDF a partir del Markdown"""
    try:
        import markdown
        from weasyprint import HTML, CSS

        # Generar markdown
        md_content = generate_markdown_report(domain, data)

        # Convertir markdown a HTML
        html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])

        # CSS profesional para el PDF
        css_content = """
        @page {
            size: A4;
            margin: 2cm;
        }
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            border-bottom: 2px solid #95a5a6;
            padding-bottom: 5px;
            margin-top: 20px;
        }
        h3 {
            color: #7f8c8d;
        }
        code {
            background-color: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background-color: #f8f8f8;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            overflow-x: auto;
        }
        ul, ol {
            margin-left: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 10px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        """

        # HTML completo
        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Reporte OSINT - {domain}</title>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """

        # Generar PDF
        pdf_bytes = HTML(string=full_html).write_pdf(stylesheets=[CSS(string=css_content)])
        return pdf_bytes

    except ImportError:
        return None

st.title("🔍 OSINT Domain Recon Pro")
st.markdown("*Herramienta profesional de reconocimiento de dominios para OSINT*")

# Inicializar base de datos
init_database()

# Sidebar para configuración
with st.sidebar:
    st.header("⚙️ Configuración")
    save_to_db = st.checkbox("💾 Guardar escaneo en base de datos", value=True)
    show_raw_data = st.checkbox("📄 Mostrar datos raw (JSON)", value=False)

    st.markdown("---")
    st.header("📚 Acerca de")
    st.markdown("""
    **OSINT Domain Recon Pro** es una herramienta profesional para analizar dominios.

    **Características:**
    - DNS completo (A, AAAA, MX, NS, TXT, SOA, CNAME)
    - Security headers HTTP
    - Certificados SSL
    - Subdominios (crt.sh)
    - Histórico de escaneos
    - Exportación MD/PDF
    """)

# Input principal
domain_input = st.text_input("🔍 Ingresa un dominio para analizar", placeholder="ejemplo.com")
domain = None
if domain_input:
    parsed = urlparse(domain_input if '://' in domain_input else f'//{domain_input}')
    domain = parsed.hostname

# Variables de exportación
export_data = {}

if domain:
    st.info(f"🎯 Analizando: **{domain}**")

    # Progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()

    # ===== RECOLECCIÓN DE DATOS =====
    status_text.text("⏳ Obteniendo registros DNS...")
    progress_bar.progress(10)
    dns_data = get_dns_records(domain)
    export_data["dns"] = dns_data

    status_text.text("⏳ Analizando headers HTTP...")
    progress_bar.progress(25)
    http_data = get_http_headers(domain)
    export_data["http"] = http_data

    status_text.text("⏳ Consultando WHOIS...")
    progress_bar.progress(40)
    try:
        whois_info = whois.whois(domain)
        export_data["whois"] = {k: str(v) for k, v in whois_info.items() if v}
    except Exception as e:
        export_data["whois"] = {"error": str(e)}

    status_text.text("⏳ Resolviendo IP y GeoIP...")
    progress_bar.progress(55)
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        export_data["ip"] = ip
        geo = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
        export_data["geoip"] = geo
    except Exception as e:
        export_data["geoip"] = {"error": str(e)}

    status_text.text("⏳ Analizando certificado SSL...")
    progress_bar.progress(70)
    if ip:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5.0)
                s.connect((domain, 443))
                cert = s.getpeercert()
                ssl_info = {
                    "Emitido a": cert.get('subject')[0][0][1],
                    "Emitido por": cert.get('issuer')[0][0][1],
                    "Válido desde": cert.get('notBefore'),
                    "Válido hasta": cert.get('notAfter'),
                    "SANs": [name for typ, name in cert.get("subjectAltName", [])]
                }
                export_data["ssl"] = ssl_info
        except Exception as e:
            export_data["ssl"] = {"error": str(e)}

    status_text.text("⏳ Buscando subdominios en crt.sh...")
    progress_bar.progress(85)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15)
        if r.ok:
            data = r.json()
            subdomains = sorted(set(entry['name_value'] for entry in data if 'name_value' in entry))
            export_data["subdomains"] = subdomains
        else:
            export_data["subdomains"] = []
    except Exception as e:
        export_data["subdomains"] = []

    # Detectar tecnologías
    if 'headers' in http_data:
        export_data["technologies"] = detect_technologies(http_data['headers'])

    progress_bar.progress(100)
    status_text.text("✅ ¡Análisis completado!")

    # Guardar en base de datos
    if save_to_db:
        scan_id = save_scan(domain, export_data)
        st.success(f"💾 Escaneo guardado en BD (ID: {scan_id})")

    st.markdown("---")

    # ===== MOSTRAR RESULTADOS CON TABS =====
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📊 Resumen",
        "🌐 DNS",
        "🔒 HTTP & Security",
        "📋 WHOIS",
        "🔐 SSL",
        "🧬 Subdominios",
        "📜 Histórico"
    ])

    with tab1:
        st.header("📊 Resumen Ejecutivo")
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("🌐 IP Principal", export_data.get('ip', 'N/A'))

        with col2:
            subdomain_count = len(export_data.get('subdomains', []))
            st.metric("🧬 Subdominios", subdomain_count)

        with col3:
            dns_count = len([k for k, v in export_data.get('dns', {}).items() if v])
            st.metric("📡 Registros DNS", dns_count)

        with col4:
            http_status = export_data.get('http', {}).get('status_code', 'N/A')
            st.metric("🌐 HTTP Status", http_status)

        st.markdown("---")

        # GeoIP
        if 'geoip' in export_data and 'error' not in export_data['geoip']:
            st.subheader("🌍 Geolocalización")
            geo = export_data['geoip']
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**🌍 País:** {geo.get('country', 'N/A')}")
                st.write(f"**📍 Región:** {geo.get('region', 'N/A')}")
            with col2:
                st.write(f"**🏙️ Ciudad:** {geo.get('city', 'N/A')}")
                st.write(f"**🏢 ISP:** {geo.get('org', 'N/A')}")

        # Tecnologías detectadas
        if 'technologies' in export_data:
            st.subheader("⚙️ Tecnologías Detectadas")
            for tech in export_data['technologies']:
                st.code(tech)

    with tab2:
        st.header("🌐 Registros DNS Completos")
        dns = export_data.get('dns', {})

        for record_type, records in dns.items():
            if records and records != ["Dominio no existe"]:
                with st.expander(f"📡 {record_type} Records ({len(records)})", expanded=True):
                    for record in records:
                        st.code(record)
            elif records == ["Dominio no existe"]:
                st.error(f"❌ {record_type}: Dominio no existe")

        if show_raw_data:
            st.json(dns)

    with tab3:
        st.header("🔒 HTTP Headers & Security")
        http = export_data.get('http', {})

        if 'error' in http:
            st.error(f"Error: {http['error']}")
        else:
            # Status y tecnologías
            col1, col2 = st.columns(2)
            with col1:
                status = http.get('status_code', 'N/A')
                st.metric("📡 Status Code", status)

            # Security Headers
            st.subheader("🛡️ Security Headers")
            if 'security_headers' in http:
                for header, value in http['security_headers'].items():
                    if "No configurado" in str(value) or "⚠️" in str(value):
                        st.error(f"❌ **{header}**: {value}")
                    else:
                        st.success(f"✅ **{header}**: {value}")

            # Redirect Chain
            if http.get('redirect_chain'):
                st.subheader("🔄 Cadena de Redirecciones")
                for i, redirect in enumerate(http['redirect_chain'], 1):
                    st.write(f"{i}. `{redirect['url']}` (Status: {redirect['status']})")

            # Headers completos
            with st.expander("📋 Todos los Headers HTTP"):
                if 'headers' in http:
                    st.json(http['headers'])

    with tab4:
        st.header("📋 Información WHOIS")
        whois_data = export_data.get('whois', {})

        if 'error' in whois_data:
            st.error(f"Error: {whois_data['error']}")
        else:
            # Mostrar campos importantes
            important_fields = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'updated_date', 'status', 'name_servers']

            for field in important_fields:
                if field in whois_data:
                    st.write(f"**{field.replace('_', ' ').title()}:** {whois_data[field]}")

            with st.expander("📄 WHOIS Completo"):
                st.json(whois_data)

    with tab5:
        st.header("🔐 Certificado SSL")
        ssl_data = export_data.get('ssl', {})

        if 'error' in ssl_data:
            st.error(f"Error: {ssl_data['error']}")
        elif ssl_data:
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Emitido a:** {ssl_data.get('Emitido a', 'N/A')}")
                st.write(f"**Emitido por:** {ssl_data.get('Emitido por', 'N/A')}")
            with col2:
                st.write(f"**Válido desde:** {ssl_data.get('Válido desde', 'N/A')}")
                st.write(f"**Válido hasta:** {ssl_data.get('Válido hasta', 'N/A')}")

            if 'SANs' in ssl_data and ssl_data['SANs']:
                st.subheader("🏷️ Subject Alternative Names (SANs)")
                for san in ssl_data['SANs']:
                    st.code(san)
        else:
            st.warning("No se encontró información SSL")

    with tab6:
        st.header("🧬 Subdominios Encontrados")
        subdomains = export_data.get('subdomains', [])

        if subdomains:
            st.success(f"✅ **{len(subdomains)} subdominios** encontrados en crt.sh")

            # Búsqueda/filtro
            search = st.text_input("🔍 Filtrar subdominios", "")
            filtered = [s for s in subdomains if search.lower() in s.lower()] if search else subdomains

            st.write(f"Mostrando {len(filtered)} de {len(subdomains)} subdominios")

            # Mostrar en columnas
            cols = st.columns(3)
            for idx, subdomain in enumerate(filtered):
                with cols[idx % 3]:
                    st.code(subdomain)

            # Exportar CSV
            if st.button("📊 Exportar subdominios a CSV"):
                df = pd.DataFrame(subdomains, columns=["Subdominio"])
                csv = df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Descargar CSV", csv, file_name=f"subdominios_{domain}.csv", mime='text/csv')
        else:
            st.warning("No se encontraron subdominios")

    with tab7:
        st.header("📜 Histórico de Escaneos")

        history = get_scan_history(domain, limit=10)

        if history:
            st.success(f"📊 **{len(history)} escaneos** anteriores encontrados")

            for scan_id, scan_date, data_json in history:
                with st.expander(f"🔍 Escaneo #{scan_id} - {scan_date}"):
                    data = json.loads(data_json)
                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.metric("IP", data.get('ip', 'N/A'))
                    with col2:
                        st.metric("Subdominios", len(data.get('subdomains', [])))
                    with col3:
                        st.metric("Status HTTP", data.get('http', {}).get('status_code', 'N/A'))

                    if st.button(f"Ver datos completos #{scan_id}"):
                        st.json(data)
        else:
            st.info("No hay escaneos previos para este dominio")

    # ===== EXPORTACIÓN =====
    st.markdown("---")
    st.header("📤 Exportar Resultados")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("📄 Exportar a Markdown", use_container_width=True):
            md_content = generate_markdown_report(domain, export_data)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_{domain}_{timestamp}.md"
            st.download_button(
                "📥 Descargar Markdown",
                md_content,
                file_name=filename,
                mime="text/markdown",
                use_container_width=True
            )

    with col2:
        if st.button("📊 Exportar datos JSON", use_container_width=True):
            json_str = json.dumps(export_data, indent=2, ensure_ascii=False)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                "📥 Descargar JSON",
                json_str,
                file_name=f"osint_{domain}_{timestamp}.json",
                mime="application/json",
                use_container_width=True
            )

    with col3:
        if st.button("📄 Exportar a PDF", use_container_width=True):
            pdf_data = generate_pdf_report(domain, export_data)
            if pdf_data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                st.download_button(
                    "📥 Descargar PDF",
                    pdf_data,
                    file_name=f"osint_{domain}_{timestamp}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.warning("⚠️ Instala las dependencias para PDF:")
                st.code("pip install markdown weasyprint")
                st.info("Por ahora, puedes exportar a Markdown y convertirlo manualmente a PDF")
