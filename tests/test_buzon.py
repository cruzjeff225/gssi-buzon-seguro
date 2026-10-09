"""Pruebas de seguridad P1 a P8 (apartado 5 de la tarea) + pruebas adicionales.

Ejecutar:  python -m pytest -v
"""
import base64
import copy
import json
import os

import pytest

import buzon_seguro as bs
from conftest import PW


def mutar_b64(texto_b64: str, pos: int = 0) -> str:
    """Cambia UN solo byte de un valor Base64."""
    raw = bytearray(base64.b64decode(texto_b64))
    raw[pos] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def enviar(home, documento, de="ana", para="beto"):
    return bs.cifrar_para(str(documento), de, para, PW[de], home)


def suplantar(home, victima="ana"):
    """Mallory reemplaza en el directorio la clave pública de 'victima' por la suya."""
    d = home / "directorio"
    falsa = (d / "mallory.pub.json").read_text(encoding="utf-8").replace('"mallory"', f'"{victima}"')
    (d / f"{victima}.pub.json").write_text(falsa, encoding="utf-8")


# ------------------------------------------------------------------ P1
def test_P1_ciclo_completo_ana_a_beto(home, documento):
    """P1: documento idéntico, hash SHA-256 coincide y firma válida."""
    paquete = enviar(home, documento)
    datos, info = bs.descifrar(paquete, "beto", PW["beto"], home)
    assert datos == documento.read_bytes()
    assert info["hash_ok"] is True and info["firma_ok"] is True
    assert info["sha256"] == bs.sha256_hex(documento.read_bytes())


def test_formato_anexo_b(home, documento):
    """El paquete respeta el Anexo B (campos y longitudes)."""
    p = enviar(home, documento)
    assert list(p) == ["version", "metadatos", "efimera_pub", "nonce", "cifrado", "firma"]
    assert p["version"] == "buzon-seguro-v1"
    assert set(p["metadatos"]) == {"remitente", "destinatario", "fecha", "archivo"}
    assert len(base64.b64decode(p["efimera_pub"])) == 32
    assert len(base64.b64decode(p["nonce"])) == 12
    assert len(base64.b64decode(p["firma"])) == 64


# ------------------------------------------------------------------ P2
@pytest.mark.parametrize("campo", ["cifrado", "nonce", "efimera_pub", "firma"])
def test_P2_un_byte_alterado_se_rechaza(home, documento, campo):
    """P2: modificar un solo byte (texto cifrado, nonce, efímera o firma) => rechazo."""
    p = enviar(home, documento)
    p[campo] = mutar_b64(p[campo], pos=0)
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(p, "beto", PW["beto"], home)


def test_P2_etiqueta_gcm_sola_detecta_la_alteracion(home, documento):
    """Sin la firma, la etiqueta GCM por sí sola ya detecta el byte cambiado."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    p = enviar(home, documento)
    priv = bs._cargar_privada(home, "beto", "x25519", PW["beto"])
    clave = bs.derivar_clave(priv.exchange(x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(p["efimera_pub"]))))
    mala = base64.b64decode(mutar_b64(p["cifrado"], 3))
    with pytest.raises(InvalidTag):
        AESGCM(clave).decrypt(base64.b64decode(p["nonce"]), mala, bs.metadatos_canonicos(p["metadatos"]))


# ------------------------------------------------------------------ P3
@pytest.mark.parametrize("campo,valor", [("destinatario", "carlos"), ("fecha", "2030-01-01T00:00:00-06:00"),
                                         ("remitente", "carlos"), ("archivo", "otro.pdf")])
def test_P3_metadatos_alterados_se_rechazan(home, documento, campo, valor):
    """P3: cambiar destinatario/fecha/etc. => rechazo (AAD autenticado y firmado)."""
    p = enviar(home, documento)
    p["metadatos"][campo] = valor
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(p, "beto", PW["beto"], home)


def test_P3_el_aad_protege_aun_con_firma_reparada(home, documento):
    """Caso extremo: aunque se 'repare' la firma (clave de Ana robada), el AAD de GCM ya no coincide."""
    p = enviar(home, documento)
    p["metadatos"]["fecha"] = "2031-05-05T10:00:00-06:00"
    priv_ana = bs._cargar_privada(home, "ana", "ed25519", PW["ana"])
    firma = priv_ana.sign(bs.datos_a_firmar(base64.b64decode(p["efimera_pub"]), base64.b64decode(p["nonce"]),
                                            p["metadatos"], base64.b64decode(p["cifrado"])))
    p["firma"] = base64.b64encode(firma).decode()
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(p, "beto", PW["beto"], home)


# ------------------------------------------------------------------ P4
def test_P4_carlos_no_puede_descifrar_paquete_de_beto(home, documento):
    """P4: Carlos confía en Ana y la firma valida, pero no puede derivar la clave => GCM falla."""
    p = enviar(home, documento)
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(p, "carlos", PW["carlos"], home)


# ------------------------------------------------------------------ P5
def _forjar_paquete_de_mallory(home):
    """Mallory arma un paquete 'de Ana' para Beto firmado con SU clave."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    meta = {"remitente": "ana", "destinatario": "beto", "fecha": "2026-10-20T14:35:00-06:00",
            "archivo": "orden_desembolso.pdf"}
    x_beto, _ = bs._cargar_publicas(home, "beto")
    ef = x25519.X25519PrivateKey.generate()
    ef_pub = bs._bytes_publicos(ef.public_key())
    clave = bs.derivar_clave(ef.exchange(x25519.X25519PublicKey.from_public_bytes(x_beto)))
    nonce = os.urandom(12)
    contenido = json.dumps({"sha256_original": bs.sha256_hex(b"PAGAR"), "datos": bs.b64(b"PAGAR")}).encode()
    cif = AESGCM(clave).encrypt(nonce, contenido, bs.metadatos_canonicos(meta))
    firma = bs._cargar_privada(home, "mallory", "ed25519", PW["mallory"]).sign(
        bs.datos_a_firmar(ef_pub, nonce, meta, cif))
    return {"version": bs.VERSION, "metadatos": meta, "efimera_pub": bs.b64(ef_pub), "nonce": bs.b64(nonce),
            "cifrado": bs.b64(cif), "firma": bs.b64(firma)}


def test_P5_mallory_reemplaza_clave_de_ana_en_el_directorio(home):
    """P5: la huella ya no coincide con la verificada => rechazo y alerta."""
    suplantar(home, "ana")
    assert bs.esta_verificada("beto", "ana", home) is False
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(_forjar_paquete_de_mallory(home), "beto", PW["beto"], home)


def test_P5_sin_verificacion_previa_el_paquete_falso_si_pasaria(home):
    """Contraste: si Beto NO hubiera anclado la huella de Ana, el engaño funcionaría.
    Esto demuestra que el control que protege es la verificación de huellas."""
    suplantar(home, "ana")
    # Beto 'verifica' a ciegas, sin comparar por otro canal (mal uso):
    bs.marcar_verificada("beto", "ana", bs.huella_usuario("ana", home), home)
    datos, info = bs.descifrar(_forjar_paquete_de_mallory(home), "beto", PW["beto"], home)
    assert datos == b"PAGAR" and info["firma_ok"]


def test_P5_comparar_con_la_huella_real_descubre_la_clave_falsa(home):
    """Si se compara con la huella REAL de Ana (leída por teléfono), la clave falsa se descubre."""
    real = bs.huella_usuario("ana", home)
    suplantar(home, "ana")
    with pytest.raises(bs.ErrorBuzon, match="NO coincide"):
        bs.marcar_verificada("beto", "ana", real, home)


def test_P5_no_se_cifra_para_destinatario_no_verificado(home, documento):
    """RF2: no se cifra para quien no ha sido verificado."""
    with pytest.raises(bs.ErrorBuzon, match="no está verificado"):
        bs.cifrar_para(str(documento), "ana", "carlos", PW["ana"], home)


def test_P5_tampoco_se_cifra_si_la_clave_cambio_despues_de_verificar(home, documento):
    suplantar(home, "beto")
    with pytest.raises(bs.ErrorBuzon, match="no está verificado"):
        bs.cifrar_para(str(documento), "ana", "beto", PW["ana"], home)


# ------------------------------------------------------------------ P6
def test_P6_contrasena_incorrecta_error_controlado(home, documento):
    """P6: error controlado, sin exponer información (mismo mensaje en cifrar y descifrar)."""
    with pytest.raises(bs.ErrorBuzon) as e1:
        bs.cifrar_para(str(documento), "ana", "beto", b"contrasena-equivocada", home)
    p = enviar(home, documento)
    with pytest.raises(bs.ErrorBuzon) as e2:
        bs.descifrar(p, "beto", b"contrasena-equivocada", home)
    assert str(e1.value) == str(e2.value) == bs.MSG_CLAVE


def test_claves_privadas_se_guardan_cifradas(home):
    pems = list((home / "privadas").glob("*.pem"))
    assert len(pems) == 8
    for pem in pems:
        assert b"BEGIN ENCRYPTED PRIVATE KEY" in pem.read_bytes()


def test_contrasena_debil_se_rechaza(tmp_path):
    with pytest.raises(bs.ErrorBuzon):
        bs.generar_identidad("zoe", b"corta", tmp_path / "d")


# ------------------------------------------------------------------ P7
def test_P7_bitacora_integra_y_luego_editada(home, documento):
    """P7: se edita una línea intermedia => 'auditar' indica la línea alterada."""
    bs.descifrar(enviar(home, documento), "beto", PW["beto"], home)
    assert bs.auditar(home)[0] is True
    log = home / "bitacora.log"
    lineas = log.read_text(encoding="utf-8").splitlines()
    objetivo = 4
    assert len(lineas) > objetivo + 1
    lineas[objetivo - 1] = lineas[objetivo - 1].replace('"usuario": "', '"usuario": "x', 1)
    log.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    ok, msg = bs.auditar(home)
    assert ok is False
    assert f"línea {objetivo} " in msg


def test_P7_borrar_lineas_finales_se_detecta(home, documento):
    enviar(home, documento)
    log = home / "bitacora.log"
    lineas = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join(lineas[:-1]) + "\n", encoding="utf-8")
    ok, msg = bs.auditar(home)
    assert ok is False and "final" in msg


def test_P7_linea_con_formato_invalido(home):
    log = home / "bitacora.log"
    lineas = log.read_text(encoding="utf-8").splitlines()
    lineas[1] = "basura"
    log.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    ok, msg = bs.auditar(home)
    assert ok is False and "línea 2" in msg


# ------------------------------------------------------------------ P8
def test_P8_mismo_documento_dos_veces_paquetes_distintos(home, documento):
    """P8: clave efímera y nonce nuevos => paquetes completamente distintos."""
    a, b = enviar(home, documento), enviar(home, documento)
    assert a["efimera_pub"] != b["efimera_pub"]
    assert a["nonce"] != b["nonce"]
    assert a["cifrado"] != b["cifrado"]
    assert a["firma"] != b["firma"]
    assert bs.descifrar(a, "beto", PW["beto"], home)[0] == bs.descifrar(b, "beto", PW["beto"], home)[0]


def test_nonces_unicos_en_muchos_envios(home, documento):
    nonces = {enviar(home, documento)["nonce"] for _ in range(200)}
    assert len(nonces) == 200


# ------------------------------------------------------------------ Extras de robustez
def test_mensaje_de_rechazo_es_identico_en_todos_los_fallos(home, documento):
    """Sin oráculo de errores: todos los rechazos producen exactamente el mismo mensaje."""
    base = enviar(home, documento)
    casos = []
    p = copy.deepcopy(base); p["cifrado"] = mutar_b64(p["cifrado"]); casos.append(p)
    p = copy.deepcopy(base); p["firma"] = mutar_b64(p["firma"]); casos.append(p)
    p = copy.deepcopy(base); p["metadatos"]["fecha"] = "x"; casos.append(p)
    p = copy.deepcopy(base); p["version"] = "otra"; casos.append(p)
    p = copy.deepcopy(base); del p["nonce"]; casos.append(p)
    p = copy.deepcopy(base); p["nonce"] = "no-es-base64!!"; casos.append(p)
    p = copy.deepcopy(base); p["metadatos"]["remitente"] = "../../etc"; casos.append(p)
    mensajes = set()
    for c in casos:
        with pytest.raises(bs.ErrorBuzon) as e:
            bs.descifrar(c, "beto", PW["beto"], home)
        mensajes.add(str(e.value))
    assert mensajes == {bs.MSG_RECHAZO}


def test_no_se_descifra_si_la_firma_falla(home, documento, monkeypatch):
    """Orden de verificación: con firma inválida jamás se abre la clave privada ni se llama a AES-GCM."""
    p = enviar(home, documento)
    p["firma"] = mutar_b64(p["firma"])

    def prohibido(*a, **k):
        raise AssertionError("se intentó descifrar/abrir clave antes de verificar la firma")
    monkeypatch.setattr(bs, "_cargar_privada", prohibido)
    monkeypatch.setattr(bs, "AESGCM", prohibido)
    with pytest.raises(bs.ErrorBuzon, match="rechazado"):
        bs.descifrar(p, "beto", PW["beto"], home)


def test_confidencialidad_el_texto_plano_no_aparece_en_el_paquete(home, documento):
    p = json.dumps(enviar(home, documento))
    assert "Solicitud de credito" not in p
    assert base64.b64encode(b"Solicitud de credito").decode() not in p


def test_usuario_invalido_se_rechaza(tmp_path):
    for malo in ("../x", "A B", "", "a/b", "x" * 100):
        with pytest.raises(bs.ErrorBuzon):
            bs.generar_identidad(malo, b"contrasena-larga-123", tmp_path / "d")


def test_cli_auditar_codigo_de_salida(home):
    assert bs.main(["--home", str(home), "auditar"]) == 0
    log = home / "bitacora.log"
    log.write_text(log.read_text(encoding="utf-8").replace("GENERAR", "GENERAX", 1), encoding="utf-8")
    assert bs.main(["--home", str(home), "auditar"]) == 2


def test_cli_flujo_completo(tmp_path, monkeypatch, capsys):
    """Recorre la CLI real (generar -> verificar -> cifrar -> descifrar -> auditar) con getpass simulado."""
    h = str(tmp_path / "d")
    monkeypatch.setattr(bs.getpass, "getpass", lambda *_: "contrasena-de-prueba-1")
    for u in ("ana", "beto"):
        assert bs.main(["--home", h, "generar", u]) == 0
    capsys.readouterr()
    assert bs.main(["--home", h, "huella", "beto"]) == 0
    huella_beto = capsys.readouterr().out.strip()
    assert bs.main(["--home", h, "verificar", "--yo", "ana", "beto", "--huella", huella_beto]) == 0
    assert bs.main(["--home", h, "verificar", "--yo", "beto", "ana", "--huella", "00"]) == 1   # huella falsa
    huella_ana = bs.formato_huella(bs.huella_usuario("ana", h))
    assert bs.main(["--home", h, "verificar", "--yo", "beto", "ana", "--huella", huella_ana]) == 0
    doc = tmp_path / "carta.txt"; doc.write_bytes(b"contenido secreto")
    paquete = tmp_path / "carta.buzon"
    assert bs.main(["--home", h, "cifrar", "--de", "ana", "--para", "beto", str(doc), "--salida", str(paquete)]) == 0
    assert bs.main(["--home", h, "descifrar", "--yo", "beto", str(paquete), "--salida", str(tmp_path / "rec")]) == 0
    assert (tmp_path / "rec" / "carta.txt").read_bytes() == b"contenido secreto"
    assert bs.main(["--home", h, "auditar"]) == 0
