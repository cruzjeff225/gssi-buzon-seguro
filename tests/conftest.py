"""Fixtures compartidos: un entorno aislado con Ana, Beto, Carlos y Mallory."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import buzon_seguro as bs  # noqa: E402

PW = {"ana": b"clave-de-ana-2026!", "beto": b"clave-de-beto-2026!",
      "carlos": b"clave-de-carlos-2026!", "mallory": b"clave-de-mallory-2026!"}


@pytest.fixture
def home(tmp_path):
    """Crea las identidades y deja a Ana y Beto con la clave del otro VERIFICADA."""
    h = tmp_path / "datos"
    for u, pw in PW.items():
        bs.generar_identidad(u, pw, h)
    # Verificación por "segundo canal": se pasa la huella real que cada dueño leería en voz alta.
    bs.marcar_verificada("ana", "beto", bs.huella_usuario("beto", h), h)
    bs.marcar_verificada("beto", "ana", bs.huella_usuario("ana", h), h)
    bs.marcar_verificada("carlos", "ana", bs.huella_usuario("ana", h), h)
    return h


@pytest.fixture
def documento(tmp_path):
    ruta = tmp_path / "solicitud_credito_0045.pdf"
    ruta.write_bytes(b"%PDF-1.4 Solicitud de credito $5,000 \x00\x01\x02" * 50)
    return ruta
