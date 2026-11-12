"""Tests that malformed / entity-bomb XML produces tool errors instead of crashing."""

from __future__ import annotations

import pytest
from defusedxml.common import DefusedXmlException

from codeguard.checkers.formatting import _parse_checkstyle_xml
from codeguard.checkers.tests import parse_junit_xml
from codeguard.config import Config

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ENTITY_BOMB_XML = b"""<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY e "boom">]>
<root>&e;</root>
"""

MALFORMED_XML = b"<unclosed>"


def _write(tmp_path, name: str, content: bytes):
    p = tmp_path / name
    p.write_bytes(content)
    return p


# ---------------------------------------------------------------------------
# parse_junit_xml (codeguard/checkers/tests.py)
# ---------------------------------------------------------------------------


def test_parse_junit_xml_entity_bomb_raises(tmp_path):
    """parse_junit_xml must raise DefusedXmlException on entity-bomb XML."""
    p = _write(tmp_path, "junit.xml", ENTITY_BOMB_XML)
    with pytest.raises(DefusedXmlException):
        parse_junit_xml(p)


def test_parse_junit_xml_malformed_returns_zeros(tmp_path):
    """Malformed (non-entity) XML silently returns zeros — not a crash."""
    p = _write(tmp_path, "junit.xml", MALFORMED_XML)
    result = parse_junit_xml(p)
    assert result == (0, 0, 0, [])


# ---------------------------------------------------------------------------
# _parse_checkstyle_xml (codeguard/checkers/formatting.py)
# ---------------------------------------------------------------------------


def test_parse_checkstyle_xml_entity_bomb_raises(tmp_path):
    """_parse_checkstyle_xml must raise DefusedXmlException on entity-bomb XML."""
    p = _write(tmp_path, "checkstyle.xml", ENTITY_BOMB_XML)
    cfg = Config(excludes=[])
    with pytest.raises(DefusedXmlException):
        _parse_checkstyle_xml(p, tmp_path, cfg)


def test_parse_checkstyle_xml_malformed_returns_empty(tmp_path):
    """Malformed XML raises ParseError — caught by the _check_java caller."""
    p = _write(tmp_path, "checkstyle.xml", MALFORMED_XML)
    cfg = Config(excludes=[])
    # defusedxml.ElementTree.ParseError IS xml.etree.ElementTree.ParseError
    import defusedxml.ElementTree as _dET

    with pytest.raises(_dET.ParseError):
        _parse_checkstyle_xml(p, tmp_path, cfg)
