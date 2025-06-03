import streamlit as st
import socket
import ssl
import whois
import requests
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

st.set_page_config(page_title="OSINT Domain Recon App", layout="wide")
st.title("🌐 OSINT Domain Recon App")

domain_input = st.text_input("🔍 Ingresa un dominio para analizar ")
domain = None
if domain_input:
    parsed = urlparse(domain_input if '://' in domain_input else f'//{domain_input}')
    domain = parsed.hostname

# Variables de exportación
export_data = {}
subdomain_list = []

if domain:
    # WHOIS
    st.header("1️⃣ WHOIS")
    try:
        whois_info = whois.whois(domain)
        export_data["whois"] = {k: str(v) for k, v in whois_info.items() if v}
        st.json(export_data["whois"])
    except Exception as e:
        st.error(f"Error al obtener WHOIS: {e}")

    # IP y GeoIP
    st.header("2️⃣ IP + GeoIP")
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        export_data["ip"] = ip
        st.write(f"🌐 IP resuelta con `socket`: `{ip}`")

        geo = requests.get(f"https://ipinfo.io/{ip}/json").json()
        export_data["geoip"] = geo
        st.json(geo)
    except socket.gaierror:
        st.warning("⚠️ No se pudo resolver el dominio a una IP. Puede que sea solo redirección HTTP o que no tenga entrada DNS directa.")
    except Exception as e:
        st.error(f"Error al resolver IP o GeoIP: {e}")

    # Certificado SSL (solo si se resolvió IP)
    st.header("3️⃣ Certificado SSL")
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
                st.json(ssl_info)
        except Exception as e:
            st.error(f"No se pudo obtener el certificado SSL: {e}")
    else:
        st.warning("❌ No se intentó obtener SSL porque no se resolvió una IP válida.")

    # crt.sh
    st.header("4️⃣ Subdominios desde crt.sh")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url)
        if r.ok:
            data = r.json()
            subdomains = sorted(set(entry['name_value'] for entry in data if 'name_value' in entry))
            subdomain_list = subdomains
            export_data["subdomains"] = subdomains
            st.write(f"🔍 Subdominios únicos encontrados: {len(subdomains)}")
            for s in subdomains:
                st.code(s)
        else:
            st.warning("No se pudo acceder a crt.sh")
    except Exception as e:
        st.error(f"Error al consultar crt.sh: {e}")

    # Exportación
    st.header("📤 Exportar Resultados")
    if st.button("📄 Exportar a Markdown"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"osint_{domain}_{timestamp}.md"
        md_content = f"# 🧠 Informe OSINT para `{domain}`\\n\\n"

        if "ip" in export_data:
            md_content += f"## 🌐 IP\\n- `{export_data['ip']}`\\n\\n"
        if "geoip" in export_data:
            md_content += f"## 🌍 GeoIP\\n```json\\n{export_data['geoip']}\\n```\\n\\n"
        if "whois" in export_data:
            md_content += f"## 🔎 WHOIS\\n```json\\n{export_data['whois']}\\n```\\n\\n"
        if "ssl" in export_data:
            md_content += f"## 🔐 SSL\\n```json\\n{export_data['ssl']}\\n```\\n\\n"
        if "subdomains" in export_data:
            md_content += f"## 🧬 Subdominios encontrados\\n"
            for sd in export_data["subdomains"]:
                md_content += f"- {sd}\\n"

        st.download_button("📥 Descargar Markdown", md_content, file_name=filename, mime="text/markdown")

    if st.button("📊 Exportar a CSV (solo subdominios)"):
        if subdomain_list:
            df = pd.DataFrame(subdomain_list, columns=["Subdominio"])
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Descargar CSV", csv, file_name=f"subdominios_{domain}.csv", mime='text/csv')
        else:
            st.warning("No hay subdominios para exportar.")
