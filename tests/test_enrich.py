from types import SimpleNamespace

from finding_pipeline import enrich


class FakeReader:
    def country(self, ip):
        if ip == "45.33.32.156":
            return SimpleNamespace(country=SimpleNamespace(name="United States"))
        raise ValueError(ip)


def test_country_found(monkeypatch):
    monkeypatch.setattr(enrich, "_reader", lambda path: FakeReader())
    assert enrich.countries_for_ips(["45.33.32.156"]) == "United States (45.33.32.156)"


def test_unknown_ip_is_skipped(monkeypatch):
    monkeypatch.setattr(enrich, "_reader", lambda path: FakeReader())
    assert enrich.countries_for_ips(["1.2.3.4"]) == ""


def test_missing_database_returns_nothing():
    assert enrich.country_for_ip("45.33.32.156", db_path="does-not-exist.mmdb") is None
