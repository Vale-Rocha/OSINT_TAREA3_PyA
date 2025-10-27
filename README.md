## Actividades pasivas con Python

Script para reconocimiento pasivo sobre dominios web. Recopila información sin interactuar activamente con los servidores más allá de consultas públicas (BuiltWith, DNS, WHOIS/RDAP, Shodan, Hunter.io y scraping básico de correos). Los resultados se guardan en CSV en `resultados_csv/<dominio>/`.

---

## Contenido

- `osint_pasivo.py` — Código principal del proyecto.
- Carpeta `resultados_csv/` — Donde se guardan los CSV generados por ejecución.

## Requisitos

- Python 3.8+ (probado en 3.13 en este equipo).
- Paquetes Python (instalables con pip):
  - builtwith
  - dnspython
  - whois11
  - requests
  - whoisit
  - pyhunter
  - shodan

## Uso

1. Abrir `osint_pasivo.py` y asignar el valor de la variable `dominio` en `main()` o adaptar el script para recibir argumentos (recomendado: usar `argparse`).
2. Ejecutar el script:

```powershell
python "Actividades pasivas con Python.py"
```

Algunas funciones piden API keys en tiempo de ejecución:
- Shodan: se pedirá la API Key cuando se invoque la función `shodan_busqueda`.
- Hunter.io: se pedirá la API Key cuando se invoque la función `hunter_busqueda`.

## Salida

Los CSV se generan en `resultados_csv/<dominio>/` con nombres con timestamp, por ejemplo:

- `builtwith_YYYYMMDD_HHMMSS.csv`
- `dns_registros_YYYYMMDD_HHMMSS.csv`
- `subdominios_encontrados_YYYYMMDD_HHMMSS.csv`
- `whois_rdap_YYYYMMDD_HHMMSS.csv`
- `shodan_YYYYMMDD_HHMMSS.csv`
- `hunter_YYYYMMDD_HHMMSS.csv`
- `correos_encontrados_YYYYMMDD_HHMMSS.csv`

Cada CSV contiene filas legibles con los campos principales extraídos por cada función.

Se genera un recopilado en formato JSON en `resultados_csv/<dominio>/reporte_pasivo_YYYYMMDD_HHMMSS.json` con todos los returns de las funciones y timestamps.

## Buenas prácticas y seguridad

- No compartas tus API keys en repositorios públicos. Guárdalas en variables de entorno o en un archivo local ignorado por git (ej. `.env`) y adapta el script para leerlas.
- Asegúrate de tener autorización para realizar reconocimiento contra el dominio objetivo. Este script puede generar consultas que, sin permiso, podrían ser inapropiadas o ilegales.
- Respeta las políticas de uso de servicios como Shodan o Hunter.io.

## Timeouts y tiempos de vida

- Se implementaron timeouts de 5 segundos (se puede modificar).
- Se implementaron lifetimes de 2-3 segundos.
## Licencia

Proyecto bajo licencia MIT. Puedes adaptar y distribuir el código respetando la licencia.

---

Notas

- Algunas integraciones requieren claves/API.
- El script requiere el dominio normalizado (sin http(s):// ni / final)
