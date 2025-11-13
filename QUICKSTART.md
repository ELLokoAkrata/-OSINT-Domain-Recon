# 🚀 Guía de Inicio Rápido - OSINT Domain Recon Pro

## Instalación en 3 pasos

### 1. Clonar e instalar dependencias

```bash
git clone https://github.com/ELLokoAkrata/-OSINT-Domain-Recon.git
cd -OSINT-Domain-Recon
pip install -r requirements.txt
```

### 2. Ejecutar la aplicación

```bash
streamlit run osint_app.py
```

### 3. Abrir en el navegador

La aplicación se abrirá automáticamente en:
```
http://localhost:8501
```

## 📝 Uso Básico

1. **Ingresa un dominio**: Escribe el dominio que quieres analizar (ej: `example.com`)
2. **Espera el análisis**: La barra de progreso muestra el estado
3. **Explora los tabs**:
   - 📊 **Resumen**: Métricas principales
   - 🌐 **DNS**: Registros DNS completos
   - 🔒 **HTTP & Security**: Headers de seguridad
   - 📋 **WHOIS**: Información de registro
   - 🔐 **SSL**: Certificado SSL
   - 🧬 **Subdominios**: Todos los subdominios encontrados
   - 📜 **Histórico**: Escaneos anteriores

## 📤 Exportar Resultados

Al final de la página encontrarás 3 botones:

- **📄 Markdown**: Reporte completo en formato MD
- **📊 JSON**: Datos estructurados
- **📄 PDF**: Reporte profesional (requiere weasyprint)

## ⚙️ Configuración (Sidebar)

- **💾 Guardar en BD**: Activa/desactiva el almacenamiento de escaneos
- **📄 Datos raw**: Muestra JSON sin procesar

## 🎯 Ejemplos de Dominios para Probar

```
google.com
github.com
stackoverflow.com
facebook.com
twitter.com
```

## 🔧 Solución de Problemas

### Si weasyprint no se instala (PDF)

No es necesario para usar la herramienta. Puedes:
1. Exportar a Markdown
2. Usar un convertidor online MD → PDF
3. O instalar weasyprint siguiendo las instrucciones en el README

### Si hay errores de DNS

El código usa DNS públicos (8.8.8.8, 1.1.1.1) automáticamente. Si sigues teniendo problemas, verifica tu conexión a internet.

## 📚 Documentación Completa

Ver [README.md](README.md) para documentación completa.

---

**¿Problemas?** Abre un issue en: https://github.com/ELLokoAkrata/-OSINT-Domain-Recon/issues
