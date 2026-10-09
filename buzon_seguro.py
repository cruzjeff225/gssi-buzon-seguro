"""
Buzón Seguro · Tarea en equipo GSSI (UNIVO)
Cooperativa Oriente Solidario: intercambio seguro de documentos.

Esquema criptográfico (cifrado híbrido, ver informe sección 4):
    - X25519 efímero + ECDH  -> secreto compartido (secreto hacia adelante)
    - HKDF-SHA256            -> clave AES de 256 bits (nunca se usa el secreto ECDH directo)
    - AES-256-GCM            -> cifrado autenticado; los metadatos viajan como AAD
    - Ed25519                -> firma del remitente sobre efimera_pub || nonce || metadatos || cifrado
    - SHA-256                -> huellas de claves, hash del documento y bitácora encadenada

Requisitos: pip install -r requirements.txt
"""
import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Constantes ---
VERSION = "buzon-seguro-v1"
INFO_HKDF = b"buzon-seguro-v1"          # contexto de la derivación (Anexo B)
GENESIS = "0" * 64                        # "hash anterior" de la primera línea de la bitácora
TAM_MAX = 50 * 1024 * 1024                # límite de 50 MB por documento (evita agotar memoria)
MIN_CONTRASENA = 12
PATRON_USUARIO = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")  # evita rutas tipo "../x"

# Mensajes: el de rechazo es deliberadamente único para no crear un "oráculo de errores".
MSG_RECHAZO = "Paquete rechazado: no se pudo verificar o descifrar."
MSG_CLAVE = "No se pudo abrir la clave privada (contraseña incorrecta o archivo dañado)."


class ErrorBuzon(Exception):
    """Error controlado cuyo mensaje es seguro mostrarlo al usuario."""


# --- Utilidades generales ---
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()


def de_b64(s: str, largo: int | None = None) -> bytes:
    """Decodifica Base64 estricto; si se indica 'largo', exige esa longitud exacta."""
    datos = base64.b64decode(s, validate=True)
    if largo is not None and len(datos) != largo:
        raise ValueError("longitud inválida")
    return datos


def sha256_hex(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def directorio_base(home: str | os.PathLike | None = None) -> Path:
    """Carpeta de datos de la aplicación (se puede cambiar con --home o BUZON_HOME)."""
    return Path(home or os.environ.get("BUZON_HOME") or "buzon_datos")


def _validar_usuario(nombre: str) -> str:
    if not isinstance(nombre, str) or not PATRON_USUARIO.match(nombre):
        raise ErrorBuzon("Nombre de usuario inválido (use minúsculas, números, '.', '_' o '-').")
    return nombre


def _ruta(home, sub: str, archivo: str) -> Path:
    d = directorio_base(home) / sub
    d.mkdir(parents=True, exist_ok=True)
    return d / archivo


def metadatos_canonicos(meta: dict) -> bytes:
    """Serialización única de los metadatos: se usa igual al firmar, cifrar (AAD) y verificar."""
    return json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# --- Bitácora encadenada (RF7) ---
def _linea_bitacora(prev: str, evento: str, usuario: str, detalle: dict) -> str:
    registro = {"ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                "evento": evento, "usuario": usuario, "detalle": detalle, "prev": prev}
    return json.dumps(registro, sort_keys=True, ensure_ascii=True)


def registrar(home, evento: str, usuario: str, detalle: dict | None = None) -> None:
    """Agrega una línea a la bitácora incluyendo el SHA-256 de la línea anterior."""
    ruta = _ruta(home, ".", "bitacora.log")
    cabeza = _ruta(home, ".", "bitacora.cabeza")
    prev = GENESIS
    if ruta.exists():
        lineas = ruta.read_text(encoding="utf-8").splitlines()
        if lineas:
            prev = sha256_hex(lineas[-1].encode())
    linea = _linea_bitacora(prev, evento, usuario, detalle or {})
    with open(ruta, "a", encoding="utf-8") as f:
        f.write(linea + "\n")
    # Ancla: hash de la última línea. Permite detectar que se borraron o editaron las líneas finales.
    cabeza.write_text(sha256_hex(linea.encode()), encoding="utf-8")


def auditar(home=None) -> tuple[bool, str]:
    """Recorre la bitácora y devuelve (íntegra, mensaje) indicando la primera línea alterada."""
    ruta = directorio_base(home) / "bitacora.log"
    cabeza = directorio_base(home) / "bitacora.cabeza"
    if not ruta.exists():
        return True, "Bitácora vacía: no hay nada que auditar."
    lineas = ruta.read_text(encoding="utf-8").splitlines()
    prev = GENESIS
    for n, linea in enumerate(lineas, start=1):
        try:
            reg = json.loads(linea)
            esperado = reg["prev"]
        except (ValueError, KeyError, TypeError):
            return False, f"ALTERADA: la línea {n} no tiene un formato válido."
        if not hmac.compare_digest(esperado, prev):
            # La línea n declara un 'prev' distinto al hash real de la n-1: la n-1 fue modificada.
            culpable = n - 1 if n > 1 else 1
            return False, (f"ALTERADA: la línea {culpable} fue modificada "
                           f"(el encadenamiento se rompe en la línea {n}).")
        prev = sha256_hex(linea.encode())
    if cabeza.exists() and not hmac.compare_digest(cabeza.read_text(encoding="utf-8").strip(), prev):
        return False, (f"ALTERADA: la última línea ({len(lineas)}) fue modificada "
                       "o se eliminaron líneas al final.")
    return True, f"Bitácora íntegra: {len(lineas)} registros encadenados correctamente."


# --- RF1: identidad (claves) · RF2: huellas y verificación ---
def _bytes_publicos(clave) -> bytes:
    return clave.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def validar_contrasena(contrasena: bytes) -> None:
    if len(contrasena) < MIN_CONTRASENA:
        raise ErrorBuzon(f"La contraseña debe tener al menos {MIN_CONTRASENA} caracteres.")


def generar_identidad(nombre: str, contrasena: bytes, home=None) -> None:
    """RF1: crea un par X25519 (cifrado) y un par Ed25519 (firma).
    Las privadas se guardan cifradas (PKCS#8 + BestAvailableEncryption); las públicas se publican."""
    nombre = _validar_usuario(nombre)
    validar_contrasena(contrasena)
    destino_x = _ruta(home, "privadas", f"{nombre}.x25519.pem")
    destino_e = _ruta(home, "privadas", f"{nombre}.ed25519.pem")
    if destino_x.exists() or destino_e.exists():
        raise ErrorBuzon("Ya existe una identidad con ese nombre; no se sobrescribe.")
    priv_x = x25519.X25519PrivateKey.generate()
    priv_e = ed25519.Ed25519PrivateKey.generate()
    cifrado = serialization.BestAvailableEncryption(contrasena)
    for ruta, priv in ((destino_x, priv_x), (destino_e, priv_e)):
        ruta.write_bytes(priv.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8, cifrado))
        try:
            os.chmod(ruta, 0o600)   # en Windows tiene efecto limitado; en Linux/macOS restringe el acceso
        except OSError:
            pass
    publica = {"version": VERSION, "usuario": nombre,
               "x25519": b64(_bytes_publicos(priv_x.public_key())),
               "ed25519": b64(_bytes_publicos(priv_e.public_key()))}
    _ruta(home, "directorio", f"{nombre}.pub.json").write_text(
        json.dumps(publica, indent=2), encoding="utf-8")
    registrar(home, "GENERAR", nombre, {"huella": huella_usuario(nombre, home)})


def _cargar_publicas(home, usuario: str) -> tuple[bytes, bytes]:
    """Lee del directorio (canal NO confiable) las claves públicas crudas de un usuario."""
    usuario = _validar_usuario(usuario)
    ruta = directorio_base(home) / "directorio" / f"{usuario}.pub.json"
    try:
        d = json.loads(ruta.read_text(encoding="utf-8"))
        return de_b64(d["x25519"], 32), de_b64(d["ed25519"], 32)
    except (OSError, ValueError, KeyError, TypeError, binascii.Error):
        raise ErrorBuzon(f"No se encontró una clave pública válida para '{usuario}'.")


def huella(clave_publica_bytes: bytes) -> str:
    """RF2: huella SHA-256 de unos bytes de clave pública (hex en mayúsculas)."""
    return sha256_hex(clave_publica_bytes).upper()


def huella_usuario(usuario: str, home=None) -> str:
    """Huella combinada de ambas claves de un usuario: cubre cifrado Y firma.
    Si alguien cambia cualquiera de las dos, la huella cambia."""
    x, e = _cargar_publicas(home, usuario)
    return huella(x + e)


def formato_huella(h: str) -> str:
    """Agrupa la huella de 4 en 4 caracteres para leerla por teléfono."""
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


def _normalizar_huella(h: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", h).upper()


def _archivo_confianza(home, yo: str) -> Path:
    return _ruta(home, "confianza", f"{_validar_usuario(yo)}.json")


def _leer_confianza(home, yo: str) -> dict:
    ruta = _archivo_confianza(home, yo)
    try:
        return json.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else {}
    except ValueError:
        return {}


def marcar_verificada(yo: str, contacto: str, huella_recibida: str, home=None) -> None:
    """RF2: 'ancla' la huella de un contacto SOLO si coincide con la que se recibió por otro canal."""
    contacto = _validar_usuario(contacto)
    real = huella_usuario(contacto, home)
    if not hmac.compare_digest(_normalizar_huella(huella_recibida), real):
        registrar(home, "VERIFICACION_FALLIDA", yo, {"contacto": contacto})
        raise ErrorBuzon("La huella NO coincide con la clave publicada. No se marca como verificada: "
                         "posible suplantación (ataque de intermediario).")
    datos = _leer_confianza(home, yo)
    datos[contacto] = real
    _archivo_confianza(home, yo).write_text(json.dumps(datos, indent=2), encoding="utf-8")
    registrar(home, "VERIFICAR", yo, {"contacto": contacto, "huella": real})


def esta_verificada(yo: str, contacto: str, home=None) -> bool:
    """True si la clave que hoy está en el directorio coincide con la huella verificada antes."""
    ancla = _leer_confianza(home, yo).get(_validar_usuario(contacto))
    if not ancla:
        return False
    try:
        return hmac.compare_digest(ancla, huella_usuario(contacto, home))
    except ErrorBuzon:
        return False


# --- Carga de claves privadas (con contraseña) ---
def _cargar_privada(home, usuario: str, tipo: str, contrasena: bytes):
    ruta = directorio_base(home) / "privadas" / f"{_validar_usuario(usuario)}.{tipo}.pem"
    try:
        return serialization.load_pem_private_key(ruta.read_bytes(), password=contrasena)
    except (ValueError, TypeError, OSError, UnsupportedAlgorithm):
        # Mismo mensaje para contraseña incorrecta, archivo faltante o dañado: no se filtra información.
        raise ErrorBuzon(MSG_CLAVE)


# --- Derivación de clave y datos firmados ---
def derivar_clave(secreto_ecdh: bytes) -> bytes:
    """HKDF-SHA256: convierte el secreto ECDH (no uniforme) en una clave AES-256 uniforme."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO_HKDF).derive(secreto_ecdh)


def datos_a_firmar(efimera_pub: bytes, nonce: bytes, meta: dict, cifrado: bytes) -> bytes:
    """Anexo B: efimera_pub || nonce || metadatos(canónicos) || cifrado."""
    return efimera_pub + nonce + metadatos_canonicos(meta) + cifrado


# --- RF3, RF4, RF6: cifrar y firmar ---
def cifrar_para(ruta_archivo: str, remitente: str, destinatario: str, contrasena: bytes,
                home=None) -> dict:
    """RF3 y RF4: ECDH efímero + HKDF + AES-256-GCM (AAD = metadatos) y firma Ed25519.
    Devuelve el paquete en el formato del Anexo B."""
    remitente = _validar_usuario(remitente)
    destinatario = _validar_usuario(destinatario)
    # RF2: jamás se cifra para alguien cuya clave no esté verificada por un segundo canal.
    if not esta_verificada(remitente, destinatario, home):
        raise ErrorBuzon(f"El destinatario '{destinatario}' no está verificado (o su clave cambió). "
                         "Compare su huella por otro canal y use el comando 'verificar'.")
    ruta = Path(ruta_archivo)
    if not ruta.is_file() or ruta.stat().st_size > TAM_MAX:
        raise ErrorBuzon("El archivo no existe o supera el tamaño máximo permitido (50 MB).")
    original = ruta.read_bytes()

    priv_firma = _cargar_privada(home, remitente, "ed25519", contrasena)   # P6: falla aquí si hay mala contraseña
    x_dest, _ = _cargar_publicas(home, destinatario)

    # Metadatos (se autentican como AAD y además se firman).
    meta = {"remitente": remitente, "destinatario": destinatario,
            "fecha": datetime.now().astimezone().isoformat(timespec="seconds"),
            "archivo": ruta.name}

    # RF3: clave efímera NUEVA por cada documento -> secreto hacia adelante y paquetes distintos (P8).
    efimera = x25519.X25519PrivateKey.generate()
    efimera_pub = _bytes_publicos(efimera.public_key())
    clave = derivar_clave(efimera.exchange(x25519.X25519PublicKey.from_public_bytes(x_dest)))
    nonce = os.urandom(12)                                                   # CSPRNG, único por mensaje

    # RF6: el hash del original viaja DENTRO del contenido cifrado.
    contenido = json.dumps({"sha256_original": sha256_hex(original), "datos": b64(original)}).encode()
    cifrado = AESGCM(clave).encrypt(nonce, contenido, metadatos_canonicos(meta))

    # RF4: firma sobre todo lo que viaja y es relevante.
    firma = priv_firma.sign(datos_a_firmar(efimera_pub, nonce, meta, cifrado))

    paquete = {"version": VERSION, "metadatos": meta, "efimera_pub": b64(efimera_pub),
               "nonce": b64(nonce), "cifrado": b64(cifrado), "firma": b64(firma)}
    registrar(home, "ENVIO", remitente, {"para": destinatario, "archivo": ruta.name,
                                         "sha256_cifrado": sha256_hex(cifrado)})
    return paquete


def guardar_paquete(paquete: dict, ruta_salida: str) -> None:
    Path(ruta_salida).write_text(json.dumps(paquete, indent=2), encoding="utf-8")


# --- RF5 y RF6: verificar firma, luego descifrar ---
def _rechazar(home, destinatario: str) -> None:
    """Registra el rechazo (sin causa) y lanza el ÚNICO mensaje genérico."""
    try:
        registrar(home, "RECHAZO", destinatario, {})
    except Exception:
        pass
    raise ErrorBuzon(MSG_RECHAZO)


def descifrar(paquete: dict, destinatario: str, contrasena: bytes, home=None) -> tuple[bytes, dict]:
    """RF5/RF6: verifica la firma ANTES de descifrar; cualquier fallo produce el mismo rechazo.
    Devuelve (documento, info) con info['hash_ok'] y info['metadatos']."""
    destinatario = _validar_usuario(destinatario)
    try:
        # 1) Estructura estricta (todo lo recibido es no confiable).
        if paquete.get("version") != VERSION:
            raise ValueError
        meta = paquete["metadatos"]
        if (not isinstance(meta, dict) or set(meta) != {"remitente", "destinatario", "fecha", "archivo"}
                or not all(isinstance(v, str) for v in meta.values())):
            raise ValueError
        efimera_pub = de_b64(paquete["efimera_pub"], 32)
        nonce = de_b64(paquete["nonce"], 12)
        cifrado = de_b64(paquete["cifrado"])
        firma = de_b64(paquete["firma"], 64)
        remitente = _validar_usuario(meta["remitente"])

        # 2) La clave del remitente debe estar VERIFICADA por el destinatario (P5: detecta suplantación).
        if not esta_verificada(destinatario, remitente, home):
            raise ValueError
        _, e_pub = _cargar_publicas(home, remitente)

        # 3) FIRMA primero: si no es auténtico, ni siquiera se toca la clave privada ni se descifra.
        ed25519.Ed25519PublicKey.from_public_bytes(e_pub).verify(
            firma, datos_a_firmar(efimera_pub, nonce, meta, cifrado))
    except (ErrorBuzon, ValueError, KeyError, TypeError, AttributeError, binascii.Error, InvalidSignature):
        _rechazar(home, destinatario)

    # 4) Recién ahora se abre la clave privada (error propio si la contraseña es incorrecta: P6).
    priv_x = _cargar_privada(home, destinatario, "x25519", contrasena)
    try:
        clave = derivar_clave(priv_x.exchange(x25519.X25519PublicKey.from_public_bytes(efimera_pub)))
        contenido = json.loads(AESGCM(clave).decrypt(nonce, cifrado, metadatos_canonicos(meta)))
        datos = de_b64(contenido["datos"])
        hash_ok = hmac.compare_digest(contenido["sha256_original"], sha256_hex(datos))   # RF6
    except (InvalidTag, ValueError, KeyError, TypeError, binascii.Error):
        # P4: un tercero (Carlos) deriva otra clave y la etiqueta GCM no valida.
        _rechazar(home, destinatario)

    registrar(home, "RECEPCION", destinatario, {"de": remitente, "archivo": meta["archivo"],
                                                "hash_ok": bool(hash_ok)})
    return datos, {"hash_ok": bool(hash_ok), "firma_ok": True, "metadatos": meta,
                   "sha256": sha256_hex(datos)}


# --- Interfaz de línea de comandos ---
def _pedir_contrasena(confirmar: bool = False) -> bytes:
    c = getpass.getpass("Contraseña de la clave privada: ")
    if confirmar and getpass.getpass("Repita la contraseña: ") != c:
        raise ErrorBuzon("Las contraseñas no coinciden.")
    return c.encode()


def _construir_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="buzon_seguro", description="Buzón Seguro · Oriente Solidario")
    p.add_argument("--home", help="carpeta de datos (por defecto ./buzon_datos o BUZON_HOME)")
    sub = p.add_subparsers(dest="accion", required=True)
    s = sub.add_parser("generar", help="RF1: crear identidad de un usuario")
    s.add_argument("usuario")
    s = sub.add_parser("huella", help="RF2: mostrar la huella de un usuario")
    s.add_argument("usuario")
    s = sub.add_parser("verificar", help="RF2: marcar como verificado a un contacto")
    s.add_argument("--yo", required=True)
    s.add_argument("contacto")
    s.add_argument("--huella", help="huella recibida por otro canal (si se omite se pide)")
    s = sub.add_parser("cifrar", help="RF3/RF4: cifrar y firmar un documento")
    s.add_argument("--de", required=True, dest="remitente")
    s.add_argument("--para", required=True, dest="destinatario")
    s.add_argument("archivo")
    s.add_argument("--salida", help="ruta del .buzon (por defecto <archivo>.buzon)")
    s = sub.add_parser("descifrar", help="RF5/RF6: verificar y descifrar un paquete")
    s.add_argument("--yo", required=True)
    s.add_argument("paquete")
    s.add_argument("--salida", default="recibidos", help="carpeta donde guardar el documento")
    sub.add_parser("auditar", help="RF7: verificar la bitácora encadenada")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _construir_parser().parse_args(argv)
    try:
        if args.accion == "generar":
            generar_identidad(args.usuario, _pedir_contrasena(confirmar=True), args.home)
            print(f"Identidad '{args.usuario}' creada. Huella: "
                  f"{formato_huella(huella_usuario(args.usuario, args.home))}")
            print("Comparta esta huella por un segundo canal (en persona o por teléfono).")
        elif args.accion == "huella":
            print(formato_huella(huella_usuario(args.usuario, args.home)))
        elif args.accion == "verificar":
            print(f"Huella de '{args.contacto}' en el directorio: "
                  f"{formato_huella(huella_usuario(args.contacto, args.home))}")
            h = args.huella or input("Escriba la huella que le dieron por otro canal: ")
            marcar_verificada(args.yo, args.contacto, h, args.home)
            print(f"'{args.contacto}' marcado como verificado.")
        elif args.accion == "cifrar":
            paquete = cifrar_para(args.archivo, args.remitente, args.destinatario,
                                  _pedir_contrasena(), args.home)
            salida = args.salida or f"{args.archivo}.buzon"
            guardar_paquete(paquete, salida)
            print(f"Paquete cifrado y firmado: {salida}")
        elif args.accion == "descifrar":
            try:
                paquete = json.loads(Path(args.paquete).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise ErrorBuzon(MSG_RECHAZO)
            datos, info = descifrar(paquete, args.yo, _pedir_contrasena(), args.home)
            print("Firma del remitente: VÁLIDA")
            print(f"Hash SHA-256 del documento: {info['sha256']} -> "
                  f"{'COINCIDE' if info['hash_ok'] else 'NO COINCIDE'}")
            if not info["hash_ok"]:
                raise ErrorBuzon(MSG_RECHAZO)
            carpeta = Path(args.salida)
            carpeta.mkdir(parents=True, exist_ok=True)
            destino = carpeta / Path(info["metadatos"]["archivo"]).name   # .name evita salirse de la carpeta
            destino.write_bytes(datos)
            print(f"Documento guardado en {destino} (remitente: {info['metadatos']['remitente']})")
        elif args.accion == "auditar":
            ok, msg = auditar(args.home)
            print(msg)
            return 0 if ok else 2
        return 0
    except ErrorBuzon as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
