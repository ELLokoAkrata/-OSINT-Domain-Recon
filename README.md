# OSINT Domain Recon App

## Descripción
OSINT Domain Recon App es una herramienta de inteligencia de código abierto (OSINT) diseñada para realizar reconocimiento básico de dominios web. Permite a los analistas de seguridad, investigadores y profesionales de TI obtener información crucial sobre dominios de forma rápida y estructurada.

## Características

- **Información WHOIS**: Obtiene datos de registro del dominio, incluyendo propietario, fechas de creación y expiración.
- **Resolución de IP y GeoIP**: Identifica la dirección IP asociada al dominio y su ubicación geográfica.
- **Análisis de Certificados SSL**: Examina el certificado SSL del dominio para validar su autenticidad y obtener información adicional.
- **Descubrimiento de Subdominios**: Utiliza crt.sh para encontrar subdominios asociados al dominio principal.
- **Exportación de Resultados**: Permite exportar los hallazgos en formatos Markdown y CSV para análisis posterior.

## Requisitos

- Python 3.7+
- Las dependencias se encuentran en el archivo `requirements.txt`

## Instalación

1. Clona este repositorio:
   ```
   git clone https://github.com/tu-usuario/osint-domain-recon.git
   cd osint-domain-recon
   ```

2. Instala las dependencias:
   ```
   pip install -r requirements.txt
   ```

## Uso

1. Inicia la aplicación:
   ```
   streamlit run osint_app.py
   ```

2. Accede a la interfaz web a través de tu navegador (normalmente en http://localhost:8501)

3. Introduce un dominio y explora los resultados en las diferentes secciones

## Limitaciones

- La aplicación depende de servicios externos como ipinfo.io y crt.sh
- Algunos dominios pueden tener restricciones en la información WHOIS disponible
- La detección de subdominios se limita a los que tienen certificados SSL registrados públicamente

## Consideraciones legales

Esta herramienta está diseñada exclusivamente para propósitos legítimos como:
- Evaluaciones de seguridad autorizadas
- Investigación de dominios propios
- Análisis de seguridad con consentimiento explícito

El uso indebido de esta herramienta para actividades no autorizadas podría violar leyes locales e internacionales.

## Contribuciones

Las contribuciones son bienvenidas. Por favor, sigue estos pasos:
1. Fork el repositorio
2. Crea una rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`)
3. Realiza tus cambios
4. Envía un pull request

## Licencia

Este proyecto está licenciado bajo MIT License - ver el archivo LICENSE para más detalles. 