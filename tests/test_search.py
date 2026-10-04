"""Tests for src/core/vault/search.py (SEARCH-1, SEARCH-2)."""

from src.core.vault.search import (
    SearchQuery,
    parse_query,
    search_entries,
)


ENTRIES = [
    {
        "id": "1",
        "title": "GitHub",
        "username": "alice@example.com",
        "url": "https://github.com",
        "notes": "work account",
        "category": "Work",
        "tags": "code,work",
    },
    {
        "id": "2",
        "title": "Gmail",
        "username": "alice@gmail.com",
        "url": "https://mail.google.com",
        "notes": "personal",
        "category": "Personal",
        "tags": "mail,important",
    },
    {
        "id": "3",
        "title": "Bank",
        "username": "bob",
        "url": "https://mybank.com",
        "notes": "",
        "category": "Finance",
        "tags": "money",
    },
]


# --------------------------------------------------------------------- #
# parse_query
# --------------------------------------------------------------------- #


def test_parse_empty() -> None:
    q = parse_query("")
    assert q.is_empty
    assert q.free_text == ""
    assert q.fields == ()


def test_parse_free_text() -> None:
    q = parse_query("github account")
    assert q.free_text == "github account"
    assert q.fields == ()


def test_parse_single_field() -> None:
    q = parse_query("title:github")
    assert q.free_text == ""
    assert q.fields == (("title", "github"),)


def test_parse_multiple_fields() -> None:
    q = parse_query("title:work category:Work")
    assert q.fields == (("title", "work"), ("category", "Work"))


def test_parse_field_plus_free_text() -> None:
    q = parse_query("work title:github")
    assert q.free_text == "work"
    assert q.fields == (("title", "github"),)


def test_parse_unknown_field_treated_as_free_text() -> None:
    q = parse_query("nonsense:value")
    assert q.free_text == "nonsense:value"
    assert q.fields == ()


def test_parse_tag_field() -> None:
    q = parse_query("tag:work")
    assert q.fields == (("tag", "work"),)


# --------------------------------------------------------------------- #
# search_entries — substring
# --------------------------------------------------------------------- #


def test_empty_query_returns_all() -> None:
    result = search_entries(ENTRIES, "")
    assert len(result) == 3


def test_free_text_matches_title() -> None:
    result = search_entries(ENTRIES, "github")
    assert [e["id"] for e in result] == ["1"]


def test_free_text_case_insensitive() -> None:
    result = search_entries(ENTRIES, "GITHUB")
    assert [e["id"] for e in result] == ["1"]


def test_free_text_matches_username() -> None:
    result = search_entries(ENTRIES, "alice")
    assert {e["id"] for e in result} == {"1", "2"}


def test_free_text_matches_url() -> None:
    result = search_entries(ENTRIES, "gmail")
    assert [e["id"] for e in result] == ["2"]


def test_free_text_matches_notes() -> None:
    result = search_entries(ENTRIES, "personal")
    assert [e["id"] for e in result] == ["2"]


def test_free_text_no_matches() -> None:
    assert search_entries(ENTRIES, "nonexistent") == []


def test_field_filter_title() -> None:
    result = search_entries(ENTRIES, "title:github")
    assert [e["id"] for e in result] == ["1"]


def test_field_filter_username() -> None:
    result = search_entries(ENTRIES, "username:alice")
    assert {e["id"] for e in result} == {"1", "2"}


def test_field_filter_category() -> None:
    result = search_entries(ENTRIES, "category:Work")
    assert [e["id"] for e in result] == ["1"]


def test_field_filter_tag() -> None:
    result = search_entries(ENTRIES, "tag:important")
    assert [e["id"] for e in result] == ["2"]


def test_multiple_fields_and_semantics() -> None:
    result = search_entries(ENTRIES, "category:Work tag:code")
    assert [e["id"] for e in result] == ["1"]


def test_multiple_fields_no_match() -> None:
    result = search_entries(ENTRIES, "category:Personal tag:code")
    assert result == []


def test_field_plus_free_text() -> None:
    result = search_entries(ENTRIES, "alice category:Work")
    assert [e["id"] for e in result] == ["1"]


# --------------------------------------------------------------------- #
# search_entries — fuzzy
# --------------------------------------------------------------------- #


def test_fuzzy_matches_typo() -> None:
    result = search_entries(ENTRIES, "githab", fuzzy=True)
    assert [e["id"] for e in result] == ["1"]


def test_fuzzy_matches_typo_username() -> None:
    result = search_entries(ENTRIES, "alise", fuzzy=True)
    assert "1" in {e["id"] for e in result}


def test_fuzzy_off_by_default() -> None:
    assert search_entries(ENTRIES, "githab") == []


def test_fuzzy_threshold_respected() -> None:
    # Very low threshold matches almost everything.
    result = search_entries(ENTRIES, "xyz", fuzzy=True, fuzzy_threshold=0.1)
    assert len(result) > 0

    # Very high threshold matches nothing.
    result = search_entries(ENTRIES, "xyz", fuzzy=True, fuzzy_threshold=0.99)
    assert result == []


# --------------------------------------------------------------------- #
# search_entries — performance (TEST related to SEARCH-2)
# --------------------------------------------------------------------- #


def test_search_scales_to_1000_entries() -> None:
    import time
    many = [
        {
            "id": str(i),
            "title": f"Entry {i}",
            "username": f"user{i}@example.com",
            "url": f"https://example.com/{i}",
            "notes": "",
            "category": "Bulk",
            "tags": "",
        }
        for i in range(1000)
    ]

    start = time.perf_counter()
    result = search_entries(many, "Entry 500")
    elapsed = time.perf_counter() - start

    assert len(result) >= 1
    assert elapsed < 0.2, f"search took {elapsed:.3f}s"