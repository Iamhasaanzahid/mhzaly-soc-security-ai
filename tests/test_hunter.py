"""Verified-surface hunter: the checks that stop false positives."""

from core import hunter


def test_origin_normalisation():
    assert hunter.origin_of("example.com") == "https://example.com"
    assert hunter.origin_of("https://example.com/path?q=1") == "https://example.com"
    assert hunter.origin_of("") == ""


def test_header_grading_full_set_is_grade_a():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    result = hunter.grade_security_headers(headers)
    assert result["grade"] == "A"
    assert result["missing"] == []


def test_header_grading_empty_is_grade_f():
    result = hunter.grade_security_headers({})
    assert result["grade"] == "F"
    assert "HSTS" in result["missing"]
    assert result["score"] == 0


def test_csp_frame_ancestors_covers_clickjacking():
    headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
    result = hunter.grade_security_headers(headers)
    assert "X-Frame-Options" not in result["missing"]


def test_cookie_flag_analysis():
    issues = hunter.analyse_cookies([
        "session=abc123; Path=/",
        "theme=dark; Secure; HttpOnly; SameSite=Lax",
    ])
    assert len(issues) == 1
    assert issues[0]["name"] == "session"
    assert "Secure flag missing" in issues[0]["issues"]


def test_parse_surface_keeps_same_origin_links_and_params():
    html = """
    <html><body>
      <a href="/about?ref=home">About</a>
      <a href="https://evil.example/steal">external</a>
      <script src="/app.js"></script>
      <form action="/login" method="post"><input name="user"></form>
      <!-- build: staging -->
    </body></html>
    """
    surface = hunter.parse_surface(html, "https://target.test/")
    assert "https://target.test/about?ref=home" in surface["links"]
    assert all("evil.example" not in link for link in surface["links"])
    assert "ref" in surface["param_names"]
    assert "https://target.test/login" in surface["form_actions"]
    assert "build: staging" in surface["comments"]


def test_leak_signature_accepts_real_env_file():
    body = "DB_HOST=localhost\nDB_PASSWORD=hunter2\n"
    assert hunter.leak_signature("/.env", body) is not None


def test_leak_signature_rejects_html_page():
    assert hunter.leak_signature("/.env", "<html><body>Welcome</body></html>") is None


def test_leak_signature_git_config():
    body = "[core]\n\trepositoryformatversion = 0\n"
    assert hunter.leak_signature("/.git/config", body) is not None


def test_soft_404_detection_same_size_and_title():
    body = "x" * 1000
    baseline = {"status": 200, "size": 1000, "title": "Not Found"}
    assert hunter.is_soft_404(200, body, baseline, title="Not Found") is True


def test_soft_404_detection_different_response():
    baseline = {"status": 404, "size": 200, "title": "Not Found"}
    assert hunter.is_soft_404(200, "y" * 5000, baseline, title="Real page") is False


def test_technology_fingerprint():
    tech = hunter.fingerprint_technologies(
        {"server": "nginx/1.25.3", "x-powered-by": "PHP/8.2"},
        "<script src='/wp-content/x.js'></script>",
    )
    assert "nginx" in tech
    assert "WordPress" in tech
    assert "PHP" in tech


def test_days_until_certificate_expiry():
    assert hunter._days_until("Jan 01 00:00:00 2000 GMT") < 0
    assert hunter._days_until("not a date") is None


def test_verify_sensitive_path_treats_401_as_protected(monkeypatch):
    class FakeResponse:
        status_code = 401
        text = "unauthorized"

    monkeypatch.setattr(hunter, "_get", lambda *a, **k: FakeResponse())
    result = hunter.verify_sensitive_path(object(), "https://t.test", "/.env", {})
    assert result["verified"] is False
    assert result["protected"] is True


def test_verify_sensitive_path_requires_signature(monkeypatch):
    class FakeResponse:
        status_code = 200
        text = "<html><body>hello</body></html>"

    monkeypatch.setattr(hunter, "_get", lambda *a, **k: FakeResponse())
    result = hunter.verify_sensitive_path(object(), "https://t.test", "/.env", {})
    assert result["verified"] is False
