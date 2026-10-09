# Buzón Seguro · Cooperativa Oriente Solidario

Herramienta de línea de comandos (Python) para enviar documentos sensibles de forma **confidencial, íntegra,
autenticada y trazable** por un canal público. Proyecto de la asignatura GSSI (UNIVO), unidad *Criptografía aplicada*.

| Pieza | Algoritmo | Función |
|---|---|---|
| Acuerdo de claves | X25519 efímero (ECDH) | Secreto compartido con secreto hacia adelante |
| Derivación | HKDF-SHA256 | Convierte el secreto ECDH en clave AES-256 |
| Cifrado | AES-256-GCM (nonce de 12 bytes aleatorio) | Confidencialidad + integridad; metadatos como AAD |
| Firma | Ed25519 | Autenticidad y no repudio del remitente |
| Hash | SHA-256 | Huellas de claves, integridad del documento, bitácora encadenada |
| Claves privadas en disco | PKCS#8 + `BestAvailableEncryption` | Protegidas con contraseña |

## Instalación

Requiere Python 3.10 o superior (Windows, macOS o Linux).

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate        macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
```

## Uso rápido (ejemplo Ana → Beto)

Los datos se guardan en `./buzon_datos` (cambie con `--home CARPETA` o la variable `BUZON_HOME`).
Las contraseñas **siempre** se piden con `getpass` (mínimo 12 caracteres).

```bash
# 1) RF1 · Cada persona crea su identidad (par X25519 + par Ed25519)
python buzon_seguro.py generar ana.lopez
python buzon_seguro.py generar beto.martinez

# 2) RF2 · Cada quien lee su huella POR OTRO CANAL (en persona / teléfono)
python buzon_seguro.py huella beto.martinez

# 3) RF2 · Ana verifica a Beto escribiendo la huella que él le dictó; Beto hace lo mismo con Ana
python buzon_seguro.py verificar --yo ana.lopez beto.martinez
python buzon_seguro.py verificar --yo beto.martinez ana.lopez

# 4) RF3/RF4/RF6 · Ana cifra y firma
python buzon_seguro.py cifrar --de ana.lopez --para beto.martinez solicitud.pdf --salida solicitud.buzon

# 5) RF5/RF6 · Beto verifica la firma y descifra (el documento queda en ./recibidos)
python buzon_seguro.py descifrar --yo beto.martinez solicitud.buzon

# 6) RF7 · Cualquiera puede auditar la bitácora (código de salida 2 si fue alterada)
python buzon_seguro.py auditar
```

Comandos: `generar`, `huella`, `verificar`, `cifrar`, `descifrar`, `auditar`. Ayuda: `python buzon_seguro.py -h`.

> Nombres de usuario: minúsculas, números, `.`, `_` o `-`.
> Cada usuario guarda *su propia* lista de contactos verificados en `confianza/<usuario>.json`
> (en un uso real cada persona la tiene en su equipo).

## Estructura de la carpeta de datos

```
buzon_datos/
├── privadas/     <usuario>.x25519.pem, <usuario>.ed25519.pem   (CIFRADAS con contraseña)
├── directorio/   <usuario>.pub.json                            (claves públicas; canal NO confiable)
├── confianza/    <usuario>.json                                (huellas verificadas por segundo canal)
├── bitacora.log  una línea JSON por evento, cada una con el SHA-256 de la anterior
└── bitacora.cabeza   hash de la última línea (detecta borrado de líneas finales)
```

## Pruebas y demostración

```bash
python -m pytest -v      # 32 pruebas automatizadas (escenarios P1 a P8 y casos de robustez)
python demo.py           # recorrido narrado de P1 a P8
```

## Formato del paquete `.buzon` (Anexo B)

```json
{ "version": "buzon-seguro-v1",
  "metadatos": {"remitente": "...", "destinatario": "...", "fecha": "...", "archivo": "..."},
  "efimera_pub": "<32 bytes B64>", "nonce": "<12 bytes B64>",
  "cifrado": "<AES-256-GCM(clave, nonce, contenido, AAD=metadatos) B64>",
  "firma": "<Ed25519 sobre efimera_pub || nonce || metadatos || cifrado, B64>" }
```

`clave = HKDF-SHA256(ECDH(efimera_priv, x25519_pub_destinatario), info = b"buzon-seguro-v1")`.
Los metadatos se serializan siempre con `json.dumps(sort_keys=True, separators=(",", ":"))`.

## Decisiones de seguridad destacadas

- **Verificar antes de descifrar:** la firma se comprueba primero; si falla no se abre la clave privada ni se llama a AES-GCM.
- **Rechazo genérico:** todos los fallos de un paquete devuelven el mismo mensaje (sin oráculo de errores).
- **Huella combinada** (X25519 ‖ Ed25519): si cambia cualquiera de las dos claves, la verificación previa deja de valer.
- **Sin cifrar para no verificados**, ni para quien cambió de clave después de verificarse.
- **Nombres validados:** evita *path traversal* (`../`) en usuarios y en el nombre del archivo recibido.
- **Sin criptografía propia:** todo proviene de la biblioteca `cryptography`; ningún secreto está en el código.
  Las contraseñas de `demo.py` y `tests/` son de identidades ficticias y temporales.

## Limitaciones conocidas

No protege contra un equipo infectado o con keylogger; no impide la repetición (*replay*) de un paquete válido
(solo registra la fecha firmada); la bitácora detecta alteraciones pero no impide que alguien con acceso total reescriba
*toda* la cadena y la cabeza. Se detallan en el informe técnico entregado en el aula virtual.

## Uso de inteligencia artificial

Se declara en el informe técnico entregado en el aula virtual.
