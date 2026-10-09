"""Demostración guiada de los escenarios P1 a P8

Uso:  python demo.py            (usa la carpeta temporal demo_datos/, se recrea en cada ejecución)
      python demo.py --pausa    (espera ENTER entre escenarios)
Las contraseñas de este archivo son SOLO de demostración y pertenecen a identidades ficticias.
"""
import base64
import json
import os
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import buzon_seguro as bs

HOME = Path("demo_datos")
PW = {"ana": b"demo-ana-2026-clave", "beto": b"demo-beto-2026-clave",
      "carlos": b"demo-carlos-2026-clave", "mallory": b"demo-mallory-2026-clave"}
PAUSA = "--pausa" in sys.argv


def titulo(txt: str) -> None:
    if PAUSA:
        input("\n[ENTER para continuar] ")
    print(f"\n{'=' * 78}\n{txt}\n{'=' * 78}")


def intentar(descripcion: str, fn) -> None:
    try:
        fn()
        print(f"  [!] {descripcion}: ACEPTADO")
    except bs.ErrorBuzon as e:
        print(f"  [OK] {descripcion}: RECHAZADO -> {e}")


def mutar(valor_b64: str) -> str:
    raw = bytearray(base64.b64decode(valor_b64))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def main() -> None:
    shutil.rmtree(HOME, ignore_errors=True)
    HOME.mkdir()
    doc = HOME / "solicitud_credito_0045.pdf"
    doc.write_bytes(b"%PDF-1.4 Solicitud de credito de Juan Perez, monto $5,000")

    titulo("PREPARACIÓN: identidades (RF1) y verificación de huellas (RF2)")
    for u in PW:
        bs.generar_identidad(u, PW[u], HOME)
        print(f"  {u:8s} huella: {bs.formato_huella(bs.huella_usuario(u, HOME))}")
    print("  (Ana y Beto se leen sus huellas por teléfono y las anclan.)")
    bs.marcar_verificada("ana", "beto", bs.huella_usuario("beto", HOME), HOME)
    bs.marcar_verificada("beto", "ana", bs.huella_usuario("ana", HOME), HOME)
    bs.marcar_verificada("carlos", "ana", bs.huella_usuario("ana", HOME), HOME)
    intentar("Ana intenta cifrar para Carlos (no verificado)",
             lambda: bs.cifrar_para(str(doc), "ana", "carlos", PW["ana"], HOME))

    titulo("P1 · Ana cifra y firma para Beto; Beto recibe y descifra")
    paquete = bs.cifrar_para(str(doc), "ana", "beto", PW["ana"], HOME)
    bs.guardar_paquete(paquete, str(HOME / "solicitud.buzon"))
    print("  Metadatos (en claro, pero autenticados):", json.dumps(paquete["metadatos"]))
    datos, info = bs.descifrar(paquete, "beto", PW["beto"], HOME)
    print(f"  Documento idéntico: {datos == doc.read_bytes()} | firma válida: {info['firma_ok']} "
          f"| SHA-256 coincide: {info['hash_ok']}\n  SHA-256: {info['sha256']}")

    titulo("P2 · Un atacante modifica UN byte del texto cifrado")
    p = json.loads(json.dumps(paquete))
    p["cifrado"] = mutar(p["cifrado"])
    intentar("Beto descifra el paquete alterado", lambda: bs.descifrar(p, "beto", PW["beto"], HOME))

    titulo("P3 · Un atacante cambia destinatario y fecha en los metadatos")
    for campo, valor in (("destinatario", "carlos"), ("fecha", "2030-01-01T00:00:00-06:00")):
        p = json.loads(json.dumps(paquete))
        p["metadatos"][campo] = valor
        intentar(f"Beto recibe el paquete con '{campo}' cambiado", lambda: bs.descifrar(p, "beto", PW["beto"], HOME))

    titulo("P4 · Carlos intenta descifrar un paquete dirigido a Beto")
    intentar("Carlos descifra el paquete de Beto", lambda: bs.descifrar(paquete, "carlos", PW["carlos"], HOME))

    titulo("P5 · Mallory reemplaza en el directorio la clave pública de Ana por la suya")
    huella_real = bs.huella_usuario("ana", HOME)
    d = HOME / "directorio"
    original_ana = (d / "ana.pub.json").read_text(encoding="utf-8")
    (d / "ana.pub.json").write_text(
        (d / "mallory.pub.json").read_text(encoding="utf-8").replace('"mallory"', '"ana"'), encoding="utf-8")
    print(f"  Huella verificada de Ana : {bs.formato_huella(huella_real)}")
    print(f"  Huella ahora en directorio: {bs.formato_huella(bs.huella_usuario('ana', HOME))}")
    print(f"  ¿Sigue verificada para Beto? {bs.esta_verificada('beto', 'ana', HOME)}")
    # Mallory firma con su clave un paquete que dice venir de Ana
    meta = {"remitente": "ana", "destinatario": "beto", "fecha": "2026-10-20T14:35:00-06:00",
            "archivo": "orden_desembolso.pdf"}
    xb, _ = bs._cargar_publicas(HOME, "beto")
    ef = x25519.X25519PrivateKey.generate()
    efp = bs._bytes_publicos(ef.public_key())
    k = bs.derivar_clave(ef.exchange(x25519.X25519PublicKey.from_public_bytes(xb)))
    n = os.urandom(12)
    cont = json.dumps({"sha256_original": bs.sha256_hex(b"PAGAR"), "datos": bs.b64(b"PAGAR")}).encode()
    c = AESGCM(k).encrypt(n, cont, bs.metadatos_canonicos(meta))
    f = bs._cargar_privada(HOME, "mallory", "ed25519", PW["mallory"]).sign(bs.datos_a_firmar(efp, n, meta, c))
    falso = {"version": bs.VERSION, "metadatos": meta, "efimera_pub": bs.b64(efp), "nonce": bs.b64(n),
             "cifrado": bs.b64(c), "firma": bs.b64(f)}
    intentar("Beto recibe el paquete 'de Ana' forjado por Mallory", lambda: bs.descifrar(falso, "beto", PW["beto"], HOME))
    intentar("Beto intenta re-verificar la clave falsa con la huella real que Ana le dictó",
             lambda: bs.marcar_verificada("beto", "ana", huella_real, HOME))
    (d / "ana.pub.json").write_text(original_ana, encoding="utf-8")   # se restaura para los demás escenarios

    titulo("P6 · Contraseña incorrecta al abrir la clave privada")
    intentar("Ana cifra con contraseña equivocada",
             lambda: bs.cifrar_para(str(doc), "ana", "beto", b"contrasena-equivocada", HOME))

    titulo("P8 · Mismo documento cifrado dos veces para el mismo destinatario")
    a = bs.cifrar_para(str(doc), "ana", "beto", PW["ana"], HOME)
    b = bs.cifrar_para(str(doc), "ana", "beto", PW["ana"], HOME)
    for campo in ("efimera_pub", "nonce", "cifrado", "firma"):
        print(f"  {campo:12s} distinto: {a[campo] != b[campo]}")

    titulo("P7 · Se edita manualmente una línea intermedia de la bitácora")
    print("  Antes :", bs.auditar(HOME)[1])
    log = HOME / "bitacora.log"
    lineas = log.read_text(encoding="utf-8").splitlines()
    lineas[3] = lineas[3].replace('"evento": "', '"evento": "X', 1)
    log.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    print("  Después:", bs.auditar(HOME)[1])
    print("\nFin de la demostración. Datos temporales en demo_datos/ (ignorados por git).")


if __name__ == "__main__":
    main()
