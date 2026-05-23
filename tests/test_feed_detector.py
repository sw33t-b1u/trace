"""Tests for ``crawler/feed_detector.detect_feed_type``."""

from __future__ import annotations

import pytest

from trace_engine.crawler.feed_detector import detect_feed_type


class TestContentTypeMapping:
    def test_rss_xml(self):
        assert detect_feed_type(content_type="application/rss+xml") == "rss"

    def test_atom_xml(self):
        assert detect_feed_type(content_type="application/atom+xml") == "atom"

    def test_rdf_xml(self):
        assert detect_feed_type(content_type="application/rdf+xml") == "rss"

    def test_text_html(self):
        assert detect_feed_type(content_type="text/html") == "html"

    def test_content_type_with_charset(self):
        assert detect_feed_type(content_type="application/atom+xml; charset=utf-8") == "atom"

    def test_case_insensitive(self):
        assert detect_feed_type(content_type="Application/RSS+XML") == "rss"

    def test_unknown_type_defaults_html(self):
        assert detect_feed_type(content_type="application/octet-stream") == "html"

    def test_no_header_defaults_html(self):
        assert detect_feed_type(content_type=None) == "html"


class TestXmlSniffing:
    """``text/xml`` and ``application/xml`` require content sniffing."""

    def test_generic_xml_with_atom_root(self):
        body = b'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        assert detect_feed_type(content_type="text/xml", content=body) == "atom"

    def test_generic_xml_with_rss_root(self):
        body = b'<?xml version="1.0"?><rss version="2.0"><channel/></rss>'
        assert detect_feed_type(content_type="application/xml", content=body) == "rss"

    def test_generic_xml_with_rdf_root(self):
        body = b'<?xml version="1.0"?><rdf:RDF xmlns:rdf="..."></rdf:RDF>'
        assert detect_feed_type(content_type="text/xml", content=body) == "rss"

    def test_generic_xml_no_content_defaults_html(self):
        # without content, generic XML cannot be classified — operator
        # must use the override.
        assert detect_feed_type(content_type="text/xml", content=None) == "html"

    def test_generic_xml_unknown_root_defaults_html(self):
        body = b"<?xml version='1.0'?><sitemapindex></sitemapindex>"
        assert detect_feed_type(content_type="text/xml", content=body) == "html"


class TestOverride:
    """``sources.yaml.feed_type`` short-circuits all detection."""

    def test_override_rss_beats_html_header(self):
        # Operator says rss even though server returns text/html.
        assert detect_feed_type(content_type="text/html", override="rss") == "rss"

    def test_override_atom_beats_octet_stream(self):
        body = b"\x00\x00\x00"
        assert (
            detect_feed_type(content_type="application/octet-stream", content=body, override="atom")
            == "atom"
        )

    def test_override_html_beats_rss_header(self):
        assert detect_feed_type(content_type="application/rss+xml", override="html") == "html"


@pytest.mark.parametrize(
    "ct, expected",
    [
        ("application/rss+xml", "rss"),
        ("application/atom+xml; charset=utf-8", "atom"),
        ("text/html; charset=utf-8", "html"),
        ("", "html"),
    ],
)
def test_table(ct, expected):
    assert detect_feed_type(content_type=ct) == expected
