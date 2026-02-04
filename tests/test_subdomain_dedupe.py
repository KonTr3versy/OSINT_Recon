from osint_posture.utils.normalize import dedupe_subdomains


def test_dedupe_and_normalize():
    names = ["*.Example.com", "foo.example.com", "FOO.example.com", "invalid..com"]
    result = dedupe_subdomains(names)
    assert result == ["example.com", "foo.example.com"]
