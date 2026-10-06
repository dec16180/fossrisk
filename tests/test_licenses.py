import pytest

from fossrisk.licenses import (And, Lic, LicenseParseError, Or, classify, leaves,
                               normalize, parse, render)


def test_parse_single_id():
    assert parse("MIT") == Lic("MIT")


def test_parse_normalizes_deprecated_ids_and_case():
    assert parse("GPL-2.0") == Lic("GPL-2.0-only")
    assert parse("GPL-2.0+") == Lic("GPL-2.0-or-later")
    assert parse("mit") == Lic("MIT")


def test_parse_compound_expression():
    node = parse("(MIT AND BSD-3-Clause) OR GPL-2.0-only WITH Classpath-exception-2.0")
    assert node == Or((And((Lic("MIT"), Lic("BSD-3-Clause"))),
                       Lic("GPL-2.0-only", "Classpath-exception-2.0")))


def test_alias_whole_string():
    assert parse("The Apache Software License, Version 2.0") == Lic("Apache-2.0")
    assert normalize("  MIT   License ") == "MIT"


def test_alias_inside_expression():
    assert parse("Apache 2.0 OR MIT") == Or((Lic("Apache-2.0"), Lic("MIT")))


def test_bare_bsd_is_not_guessed():
    assert classify(parse("BSD")).category == "unknown"


@pytest.mark.parametrize("bad", ["", "   ", "(MIT", "MIT AND", "MIT OR OR GPL-2.0-only"])
def test_parse_errors(bad):
    with pytest.raises(LicenseParseError):
        parse(bad)


def test_render_round_trip():
    text = "(MIT AND BSD-3-Clause) OR GPL-2.0-only WITH Classpath-exception-2.0"
    assert render(parse(text)) == text


def test_leaves():
    assert leaves(parse("MIT AND (Apache-2.0 OR ISC)")) == [Lic("MIT"), Lic("Apache-2.0"), Lic("ISC")]


@pytest.mark.parametrize("spdx_id,category", [
    ("MIT", "permissive"),
    ("CC0-1.0", "public-domain"),
    ("LGPL-2.1-only", "weak-copyleft"),
    ("MPL-2.0", "weak-copyleft"),
    ("GPL-3.0-or-later", "strong-copyleft"),
    ("AGPL-3.0-only", "network-copyleft"),
    ("CC-BY-NC-4.0", "non-commercial"),
    ("LicenseRef-Proprietary", "proprietary"),
    ("LicenseRef-acme-internal", "unknown"),
])
def test_classify_categories(spdx_id, category):
    assert classify(Lic(spdx_id)).category == category


def test_classify_is_case_insensitive_and_returns_canonical_id():
    info = classify(Lic("apache-2.0"))
    assert info.id == "Apache-2.0"
    assert info.obligations == ("attribution", "include-license-text", "notice-file", "state-changes")


def test_exception_relaxes_copyleft_only():
    assert classify(Lic("GPL-2.0-only", "Classpath-exception-2.0")).category == "weak-copyleft"
    assert classify(Lic("Apache-2.0", "LLVM-exception")).category == "permissive"
    assert classify(Lic("GPL-2.0-only", "Made-up-exception")).category == "strong-copyleft"


@pytest.mark.parametrize("text", ["LicenseRef-acme or later", "MIT Or Apache-2.0", "MIT and ISC"])
def test_non_uppercase_operators_are_rejected(text):
    with pytest.raises(LicenseParseError, match="uppercase"):
        parse(text)


def test_free_text_or_later_aliases():
    assert parse("GPLv2 or later") == Lic("GPL-2.0-or-later")


def test_deprecated_with_ids_expand_inside_expressions():
    assert parse("MIT OR GPL-2.0-with-classpath-exception") == Or(
        (Lic("MIT"), Lic("GPL-2.0-only", "Classpath-exception-2.0")))
