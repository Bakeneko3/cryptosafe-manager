"""Tests for src/core/import_export/formats/* (FMT-1, FMT-3, IMP-1)."""

import json

import pytest

from src.core.import_export.formats import (
    bitwarden_format,
    csv_format,
    json_format,
    lastpass_format,
)


SAMPLE = [
    {
        "title": "GitHub",
        "username": "alice",
        "password": "hunter2",
        "url": "https://github.com",
        "notes": "2FA",
        "category": "Work",
        "tags": "code,work",
    },
    {
        "title": "Gmail",
        "username": "alice@gmail.com",
        "password": "hunter3",
        "url": "https://mail.google.com",
        "notes": "",
        "category": "Personal",
        "tags": "",
    },
]


# --------------------------------------------------------------------- #
# JSON format (FMT-1)
# --------------------------------------------------------------------- #


def test_json_roundtrip() -> None:
    data = json_format.render(SAMPLE)
    parsed = json_format.parse(data)
    assert len(parsed) == 2
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["password"] == "hunter2"
    assert parsed[1]["title"] == "Gmail"


def test_json_document_fields() -> None:
    data = json_format.render(SAMPLE)
    doc = json.loads(data.decode("utf-8"))
    assert doc["cryptosafe_export"] is True
    assert doc["version"] == "1.0"
    assert doc["entry_count"] == 2
    assert "timestamp" in doc
    assert "source" in doc


def test_json_unicode() -> None:
    entries = [{"title": "Привет 🎉", "password": "…"}]
    data = json_format.render(entries)
    parsed = json_format.parse(data)
    assert parsed[0]["title"] == "Привет 🎉"


def test_json_rejects_non_cryptosafe() -> None:
    with pytest.raises(json_format.JsonFormatError):
        json_format.parse(b'{"items": []}')


def test_json_rejects_garbage() -> None:
    with pytest.raises(json_format.JsonFormatError):
        json_format.parse(b"not json")


# --------------------------------------------------------------------- #
# Generic CSV
# --------------------------------------------------------------------- #


def test_csv_roundtrip() -> None:
    data = csv_format.render(SAMPLE)
    parsed = csv_format.parse(data)
    assert len(parsed) == 2
    assert parsed[0]["title"] == "GitHub"


def test_csv_handles_special_characters() -> None:
    entries = [
        {
            "title": 'Tricky, "quoted"',
            "password": "line1\nline2",
            "notes": "comma, and, more",
        }
    ]
    data = csv_format.render(entries)
    parsed = csv_format.parse(data)
    assert parsed[0]["title"] == 'Tricky, "quoted"'
    assert parsed[0]["password"] == "line1\nline2"


def test_csv_rejects_empty() -> None:
    with pytest.raises(csv_format.CsvFormatError):
        csv_format.parse(b"")


# --------------------------------------------------------------------- #
# Bitwarden
# --------------------------------------------------------------------- #


def test_bitwarden_render_parse_roundtrip() -> None:
    data = bitwarden_format.render(SAMPLE)
    parsed = bitwarden_format.parse(data)
    assert len(parsed) == 2
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["username"] == "alice"
    assert parsed[0]["password"] == "hunter2"
    assert parsed[0]["url"] == "https://github.com"


def test_bitwarden_import_real_structure() -> None:
    """Parse a realistic Bitwarden export (documented schema)."""
    doc = {
        "encrypted": False,
        "folders": [{"id": "f-1", "name": "Work"}],
        "items": [
            {
                "id": "it-1",
                "folderId": "f-1",
                "type": 1,
                "name": "GitHub",
                "notes": "2FA enabled",
                "login": {
                    "uris": [{"match": None, "uri": "https://github.com"}],
                    "username": "alice",
                    "password": "hunter2",
                    "totp": None,
                },
            },
            {
                "id": "it-2",
                "type": 2,  # Secure note
                "name": "Notes",
                "notes": "Some private notes",
            },
        ],
    }
    parsed = bitwarden_format.parse(json.dumps(doc).encode("utf-8"))
    assert len(parsed) == 2
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["category"] == "Work"
    assert parsed[1]["title"] == "Notes"
    assert parsed[1]["notes"] == "Some private notes"


def test_bitwarden_rejects_non_export() -> None:
    with pytest.raises(bitwarden_format.BitwardenFormatError):
        bitwarden_format.parse(b'{"folders": []}')


def test_bitwarden_rejects_garbage() -> None:
    with pytest.raises(bitwarden_format.BitwardenFormatError):
        bitwarden_format.parse(b"not json")


# --------------------------------------------------------------------- #
# LastPass
# --------------------------------------------------------------------- #


def test_lastpass_roundtrip() -> None:
    data = lastpass_format.render(SAMPLE)
    parsed = lastpass_format.parse(data)
    assert len(parsed) == 2
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["password"] == "hunter2"


def test_lastpass_import_real_structure() -> None:
    csv = (
        "url,username,password,extra,name,grouping,fav\n"
        "https://github.com,alice,hunter2,2FA,"
        "GitHub,Work,0\n"
    )
    parsed = lastpass_format.parse(csv.encode("utf-8"))
    assert len(parsed) == 1
    assert parsed[0]["url"] == "https://github.com"
    assert parsed[0]["username"] == "alice"
    assert parsed[0]["password"] == "hunter2"
    assert parsed[0]["notes"] == "2FA"
    assert parsed[0]["title"] == "GitHub"
    assert parsed[0]["category"] == "Work"


def test_lastpass_rejects_wrong_header() -> None:
    with pytest.raises(lastpass_format.LastPassFormatError):
        lastpass_format.parse(b"a,b,c\n1,2,3\n")