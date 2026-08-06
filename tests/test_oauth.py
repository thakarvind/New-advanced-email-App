import app


def test_resolve_account_email_prefers_userinfo_when_id_token_is_not_a_dict():
    creds = type("Creds", (), {"id_token": "signed-jwt", "token": "abc123"})()

    assert app._resolve_account_email(creds, {"email": "user@example.com"}) == "user@example.com"


def test_resolve_gmail_redirect_uri_uses_app_base_url_when_not_configured():
    settings = app.Settings(gmail_redirect_uri="", app_base_url="https://mail.example.com")

    assert settings.resolve_gmail_redirect_uri() == "https://mail.example.com/auth/gmail/callback"
