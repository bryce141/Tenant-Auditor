"""Tests for presentation helpers.

Internal identifiers reaching the UI is the specific thing these prevent —
report rows showed "mail_security" where a person expects "Mail Security".
"""
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app.services.formatting import (distinct_history, relative_time, report_type_label,
                                     score_tone, short_datetime)
from app.utils import utcnow


@pytest.mark.parametrize("raw,expected", [
    ("mail_security", "Mail Security"),
    ("conditional_access", "Conditional Access"),
    ("identity", "Identity & Access"),
    ("full", "Full audit"),
    ("sharepoint", "SharePoint"),
])
def test_known_types_get_written_labels(raw, expected):
    assert report_type_label(raw) == expected


def test_unknown_type_is_still_readable():
    """An unmapped type must not leak snake_case to the user."""
    assert report_type_label("some_new_category") == "Some New Category"
    assert "_" not in report_type_label("some_new_category")


def test_no_report_type_maps_to_a_dash():
    assert report_type_label(None) == "—"
    assert report_type_label("") == "—"


@pytest.mark.parametrize("delta,expected", [
    (timedelta(seconds=5), "just now"),
    (timedelta(minutes=1), "1 min ago"),
    (timedelta(minutes=30), "30 min ago"),
    (timedelta(hours=1), "1 hour ago"),
    (timedelta(hours=5), "5 hours ago"),
    (timedelta(days=1, hours=2), "yesterday"),
    (timedelta(days=3), "3 days ago"),
])
def test_relative_time_reads_naturally(delta, expected):
    assert relative_time(utcnow() - delta) == expected


def test_relative_time_falls_back_to_a_date_when_ago_stops_helping():
    """'47 days ago' is worse than a date."""
    old = utcnow() - timedelta(days=47)
    assert relative_time(old) == old.strftime("%d %b %Y")


def test_relative_time_handles_missing_and_future_values():
    assert relative_time(None) == "—"
    assert relative_time(utcnow() + timedelta(hours=1)) == "just now"


def test_short_datetime_is_exact():
    from datetime import datetime
    assert short_datetime(datetime(2026, 9, 8, 15, 4)) == "8 Sep 2026, 15:04"


@pytest.mark.parametrize("score,tone", [
    (95, "emerald"), (70, "amber"), (45, "orange"), (20, "red"),
])
def test_score_tone_distinguishes_bands(score, tone):
    assert tone in score_tone(score)


def test_score_tone_does_not_paint_everything_red():
    """A colour that applies to every value carries no information."""
    tones = {score_tone(s) for s in (95, 70, 45, 20)}
    assert len(tones) == 4, "each band needs its own tone"


def test_missing_score_is_neutral():
    assert "slate" in score_tone(None)


def test_history_collapses_to_one_point_per_day():
    """A full audit writes several reports seconds apart on the same day."""
    now = utcnow()
    reports = [
        SimpleNamespace(created_at=now - timedelta(days=2), score=30),
        SimpleNamespace(created_at=now - timedelta(days=1), score=35),
        SimpleNamespace(created_at=now - timedelta(seconds=30), score=40),
        SimpleNamespace(created_at=now - timedelta(seconds=20), score=41),
        SimpleNamespace(created_at=now - timedelta(seconds=10), score=45),
    ]

    result = distinct_history(reports)

    assert len(result) == 3, "three distinct days"
    assert result[-1].score == 45, "keeps the last reading of each day"
    assert [r.score for r in result] == [30, 35, 45]


def test_history_ignores_reports_without_a_score():
    now = utcnow()
    reports = [SimpleNamespace(created_at=now, score=None),
               SimpleNamespace(created_at=now - timedelta(days=1), score=50)]
    assert [r.score for r in distinct_history(reports)] == [50]



# --------------------------------------------------------------- strip_html

@pytest.mark.parametrize("raw,expected", [
    ("<p>Assign more than one user a global administrator role.</p>",
     "Assign more than one user a global administrator role"),
    ("Go to Entra ID &gt; Enterprise applications", "Go to Entra ID > Enterprise applications"),
    ("<br/>spaced<br>out", "spaced out"),
    ("", ""),
    (None, ""),
    ("plain text, no markup", "plain text, no markup"),
])
def test_strip_html_produces_readable_text(raw, expected):
    from app.utils import strip_html
    assert strip_html(raw) == expected


def test_list_items_become_sentences_not_a_run_on():
    """Microsoft returns remediation as <ol><li>, which would otherwise merge."""
    from app.utils import strip_html
    out = strip_html("<ol><li>First step</li><li>Second step</li></ol>")
    assert out == "First step. Second step"


def test_no_tags_survive_stripping():
    """Entities become their characters — &gt; should read as '>', not vanish."""
    from app.utils import strip_html
    out = strip_html('<ol><li>Go to <a href="https://x">Entra</a> &gt; apps</li></ol>')

    assert "<" not in out, "no tags may remain"
    assert "href" not in out
    assert out == "Go to Entra > apps"
if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
