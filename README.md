# 🔍 OSINT Domain Recon Pro

## Descripción
**OSINT Domain Recon Pro** es una herramienta profesional de inteligencia de código abierto (OSINT) diseñada para realizar reconocimiento completo de dominios web. Permite a los analistas de seguridad, investigadores y profesionales de TI obtener información detallada sobre dominios de forma rápida, estructurada y profesional.

## ✨ Características Principales

### 🌐 Análisis DNS Completo
- **Registros A**: IPv4 del dominio
- **Registros AAAA**: IPv6 del dominio
- **Registros MX**: Servidores de correo
- **Registros NS**: Servidores de nombres
- **Registros TXT**: SPF, DMARC, verificaciones de dominio
- **Registros CNAME**: Alias del dominio
- **Registros SOA**: Información de autoridad

### 🔒 Análisis HTTP & Seguridad
- **Headers HTTP completos**: Todos los headers de respuesta del servidor
- **Security Headers**: Análisis de cabeceras de seguridad
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
- **Redirect Chain**: Cadena completa de redirecciones
- **Detección de tecnologías**: Servidor web, frameworks, CMS

### 📋 Información WHOIS
- Propietario del dominio
- Registrador
- Fechas de creación, actualización y expiración
- Estado del dominio
- Servidores de nombres

### 🌍 GeoIP
- País, región y ciudad
- ISP y organización
- Coordenadas geográficas

### 🔐 Certificados SSL
- Emisor y sujeto del certificado
- Fechas de validez
- Subject Alternative Names (SANs)

### 🧬 Descubrimiento de Subdominios
- Búsqueda en Certificate Transparency Logs (crt.sh)
- Filtrado y búsqueda de subdominios
- Exportación de subdominios a CSV

### 💾 Base de Datos de Históricos
- Almacenamiento automático de escaneos en SQLite
- Comparación de escaneos anteriores
- Detección de cambios en el tiempo
- Histórico completo por dominio

### 📤 Exportación Profesional
- **Markdown**: Reportes completos con toda la información
- **JSON**: Datos estructurados para integración
- **PDF**: Reportes profesionales con estilo (requiere weasyprint)
- **CSV**: Subdominios en formato tabular

## 📋 Requisitos

- Python 3.7+
- Las dependencias se encuentran en el archivo `requirements.txt`

## 🚀 Instalación

### Instalación Básica

1. Clona este repositorio:
   ```bash
   git clone https://github.com/ELLokoAkrata/-OSINT-Domain-Recon.git
   cd -OSINT-Domain-Recon
   ```

2. Instala las dependencias básicas:
   ```bash
   pip install -r requirements.txt
   ```

### Instalación con soporte PDF (Opcional)

Para habilitar la exportación a PDF, instala las dependencias adicionales:

**En Linux/macOS:**
```bash
# Instalar dependencias del sistema para weasyprint
sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

# O en macOS:
brew install cairo pango gdk-pixbuf libffi

pip install markdown weasyprint
```

**En Windows:**
```bash
# Descargar GTK3 desde: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
# Luego instalar las librerías Python
pip install markdown weasyprint
```

## 💻 Uso

### Inicio Rápido

1. Inicia la aplicación:
   ```bash
   streamlit run osint_app.py
   ```

2. Accede a la interfaz web a través de tu navegador:
   ```
   http://localhost:8501
   ```

3. Ingresa un dominio (ejemplo: `google.com`) y presiona Enter

4. Explora los resultados organizados en 7 tabs:
   - **📊 Resumen**: Vista general con métricas clave
   - **🌐 DNS**: Todos los registros DNS del dominio
   - **🔒 HTTP & Security**: Headers HTTP y security headers
   - **📋 WHOIS**: Información de registro del dominio
   - **🔐 SSL**: Detalles del certificado SSL
   - **🧬 Subdominios**: Lista completa de subdominios encontrados
   - **📜 Histórico**: Escaneos anteriores del mismo dominio

### Opciones de Configuración (Sidebar)

- **💾 Guardar escaneo en base de datos**: Habilita/deshabilita el almacenamiento automático
- **📄 Mostrar datos raw (JSON)**: Muestra los datos crudos en formato JSON

### Exportación de Resultados

La aplicación ofrece 3 formatos de exportación:

1. **📄 Markdown (.md)**: Reporte completo y legible
2. **📊 JSON (.json)**: Datos estructurados para procesamiento
3. **📄 PDF (.pdf)**: Reporte profesional con estilo (requiere weasyprint)

## 🗄️ Base de Datos

Los escaneos se guardan automáticamente en `osint_scans.db` (SQLite). Esto permite:

- Ver histórico de cambios en un dominio
- Comparar escaneos anteriores
- Detectar nuevos subdominios o cambios en la infraestructura
- Análisis de tendencias

## 🎯 Casos de Uso

### Pentesting y Red Team
- Reconocimiento inicial de objetivos
- Descubrimiento de subdominios
- Análisis de configuraciones de seguridad
- Detección de tecnologías utilizadas

### Blue Team y Defensa
- Auditoría de security headers propios
- Monitoreo de cambios en infraestructura
- Verificación de configuraciones DNS
- Control de certificados SSL

### Investigación OSINT
- Investigación de dominios sospechosos
- Análisis de infraestructura de phishing
- Mapeo de organizaciones
- Descubrimiento de relaciones entre dominios

### Bug Bounty
- Enumeración de subdominios
- Identificación de superficie de ataque
- Descubrimiento de assets no documentados

## ⚠️ Limitaciones

- La aplicación depende de servicios externos:
  - **ipinfo.io**: Geolocalización de IPs (gratis, sin API key)
  - **crt.sh**: Certificate Transparency Logs (gratis)
  - Resolvers DNS públicos
- Algunos dominios pueden tener restricciones WHOIS (privacy protection)
- La detección de subdominios se limita a certificados SSL públicos
- Security headers solo detectables si el sitio responde HTTP/HTTPS
- No requiere API keys de pago (100% gratuito)

## ⚖️ Consideraciones Legales

Esta herramienta está diseñada **exclusivamente** para propósitos legítimos como:

- ✅ Evaluaciones de seguridad autorizadas
- ✅ Investigación de dominios propios
- ✅ Análisis de seguridad con consentimiento explícito
- ✅ Educación e investigación en ciberseguridad
- ✅ Bug bounty programs autorizados
- ✅ Auditorías de seguridad profesionales

**⚠️ ADVERTENCIA**: El uso indebido de esta herramienta para actividades no autorizadas podría violar leyes locales e internacionales sobre:
- Acceso no autorizado a sistemas informáticos
- Violación de privacidad
- Términos de servicio de terceros

**El usuario es el único responsable del uso que haga de esta herramienta.**

## 🆚 Comparación con Herramientas Similares

| Característica | OSINT Domain Recon Pro | theHarvester | Recon-ng | Amass |
|----------------|------------------------|--------------|----------|-------|
| Interfaz Web | ✅ | ❌ | ❌ | ❌ |
| Sin API Keys | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Base de Datos | ✅ | ❌ | ✅ | ❌ |
| Security Headers | ✅ | ❌ | ❌ | ❌ |
| DNS Completo | ✅ | ⚠️ | ✅ | ✅ |
| Export PDF | ✅ | ❌ | ❌ | ❌ |
| Histórico | ✅ | ❌ | ⚠️ | ❌ |
| Fácil de usar | ✅✅ | ⚠️ | ⚠️ | ⚠️ |

## 🚧 Roadmap / Futuras Mejoras

- [ ] Integración con Shodan (opcional, con API key)
- [ ] Análisis de puertos comunes (port scanning básico)
- [ ] Detección de WAF (Web Application Firewall)
- [ ] Análisis de robots.txt, sitemap.xml, security.txt
- [ ] Integración con Wayback Machine
- [ ] Búsqueda de emails relacionados
- [ ] Análisis de archivos JavaScript expuestos
- [ ] Detección de frameworks frontend
- [ ] API REST para automatización
- [ ] CLI mode (sin interfaz web)
- [ ] Notificaciones de cambios (webhooks)
- [ ] Gráficos y visualizaciones de relaciones
- [ ] Integración con MISP

## 🤝 Contribuciones

Las contribuciones son **muy bienvenidas**. Para contribuir:

1. Fork el repositorio
2. Crea una rama para tu funcionalidad:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. Realiza tus cambios y commitea:
   ```bash
   git commit -m "feat: descripción de la funcionalidad"
   ```
4. Push a tu fork:
   ```bash
   git push origin feature/nueva-funcionalidad
   ```
5. Abre un Pull Request

### Ideas para Contribuir

- 🐛 Reportar bugs
- 📝 Mejorar documentación
- ✨ Añadir nuevas fuentes de datos gratuitas
- 🎨 Mejorar la UI/UX
- 🌍 Traducciones a otros idiomas
- 🧪 Añadir tests

## 📞 Soporte

Si encuentras algún problema o tienes sugerencias:

1. Revisa los [Issues existentes](https://github.com/ELLokoAkrata/-OSINT-Domain-Recon/issues)
2. Si no existe, crea un [nuevo Issue](https://github.com/ELLokoAkrata/-OSINT-Domain-Recon/issues/new)
3. Proporciona la mayor información posible:
   - Versión de Python
   - Sistema operativo
   - Pasos para reproducir el error
   - Logs de error

## 📄 Licencia

Este proyecto está licenciado bajo **MIT License**.

```
MIT License

Copyright (c) 2024 OSINT Domain Recon Pro

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia
de este software y archivos de documentación asociados (el "Software"), para usar
el Software sin restricciones, incluyendo sin limitación los derechos de usar,
copiar, modificar, fusionar, publicar, distribuir, sublicenciar y/o vender copias
del Software, bajo las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las
copias o porciones sustanciales del Software.

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO.
```

## 🌟 Créditos

Desarrollado con ❤️ para la comunidad OSINT y Ciberseguridad.

**Herramientas y servicios utilizados:**
- [Streamlit](https://streamlit.io/) - Framework web
- [crt.sh](https://crt.sh/) - Certificate Transparency Logs
- [ipinfo.io](https://ipinfo.io/) - Geolocalización de IPs
- [python-whois](https://github.com/richardpenman/whois) - WHOIS lookup
- [dnspython](https://www.dnspython.org/) - DNS toolkit

---

**⭐ Si te gusta este proyecto, dale una estrella en GitHub!** 