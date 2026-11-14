from __future__ import annotations

import requests
from types import SimpleNamespace

from multi_domain_ids.threat_intelligence import (
    AbuseIPDBProvider,
    IOCMatcher,
    OpenCTIProvider,
    OTXProvider,
    ThreatIntelligenceCache,
    ThreatIntelligenceService,
    VirusTotalProvider,
    aggregate_reputation,
    build_threat_intelligence_service,
)


class _Response:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


def test_four_provider_adapters_parse_mocked_api_responses(monkeypatch):
    from multi_domain_ids.threat_intelligence import abuseipdb, opencti, otx, virustotal

    opencti_response = {
        "data": {
            "indicators": {
                "edges": [
                    {
                        "node": {
                            "id": "indicator-1",
                            "pattern": "[ipv4-addr:value = '203.0.113.8']",
                        }
                    }
                ]
            }
        }
    }
    monkeypatch.setattr(
        abuseipdb,
        "requests",
        SimpleNamespace(get=lambda *args, **kwargs: _Response({"data": {"abuseConfidenceScore": 82, "totalReports": 9}})),
    )
    monkeypatch.setattr(
        virustotal,
        "requests",
        SimpleNamespace(get=lambda *args, **kwargs: _Response({"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}})),
    )
    monkeypatch.setattr(
        otx,
        "requests",
        SimpleNamespace(get=lambda *args, **kwargs: _Response({"pulse_info": {"count": 2}, "indicator": []})),
    )
    monkeypatch.setattr(
        opencti,
        "requests",
        SimpleNamespace(post=lambda *args, **kwargs: _Response(opencti_response)),
    )

    providers = [
        AbuseIPDBProvider(api_key="mock", enabled=True),
        VirusTotalProvider(api_key="mock", enabled=True),
        OTXProvider(api_key="mock", enabled=True),
        OpenCTIProvider(url="https://opencti.invalid", api_key="mock", enabled=True),
    ]
    results = ThreatIntelligenceService(providers).lookup("203.0.113.8")

    assert results["abuseipdb"]["abuse_confidence_score"] == 82
    assert results["virustotal"]["malicious_count"] == 3
    assert results["otx"]["pulse_count"] == 2
    assert results["opencti"]["indicators"][0]["id"] == "indicator-1"
    assert all(result["available"] for result in results.values())


def test_provider_failure_is_reported_without_blocking_other_providers(monkeypatch):
    def fail(*args, **kwargs):
        raise requests.ConnectionError("mock outage")

    from multi_domain_ids.threat_intelligence import abuseipdb, virustotal

    monkeypatch.setattr(virustotal, "requests", SimpleNamespace(get=fail))
    monkeypatch.setattr(
        abuseipdb,
        "requests",
        SimpleNamespace(get=lambda *args, **kwargs: _Response({"data": {"abuseConfidenceScore": 0}})),
    )
    service = ThreatIntelligenceService(
        [
            VirusTotalProvider(api_key="mock", enabled=True),
            AbuseIPDBProvider(api_key="mock", enabled=True),
        ]
    )

    results = service.lookup("203.0.113.8")

    assert results["virustotal"]["available"] is False
    assert results["virustotal"]["error"] == "connectionerror"
    assert results["abuseipdb"]["available"] is True


def test_cache_prevents_repeated_provider_requests(monkeypatch):
    calls = []

    def get(*args, **kwargs):
        calls.append(1)
        return _Response({"data": {"abuseConfidenceScore": 0}})

    from multi_domain_ids.threat_intelligence import abuseipdb

    monkeypatch.setattr(abuseipdb, "requests", SimpleNamespace(get=get))
    provider = AbuseIPDBProvider(
        api_key="mock",
        enabled=True,
        cache=ThreatIntelligenceCache(ttl_seconds=60),
    )

    first = provider.lookup("203.0.113.8")
    second = provider.lookup("203.0.113.8")

    assert len(calls) == 1
    assert first == second


def test_ioc_matching_aggregation_and_environment_factory(monkeypatch):
    provider_results = {
        "otx": {
            "provider": "otx",
            "ip": "203.0.113.8",
            "available": True,
            "pulse_count": 2,
            "relevant_indicators": ["203.0.113.8"],
        }
    }
    matches = IOCMatcher().match(
        {"source_ip": "203.0.113.8"},
        provider_results,
        known_iocs=[{"value": "203.0.113.8", "source": "local-list"}],
    )
    summary = aggregate_reputation(provider_results)

    assert {match["source"] for match in matches} == {"otx", "local-list"}
    assert summary["providers_reporting_malicious"] == 1
    assert summary["consensus"] == "malicious"

    monkeypatch.setenv("THREAT_INTEL_ENABLED", "true")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "mock-abuse")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "mock-vt")
    monkeypatch.setenv("OTX_API_KEY", "mock-otx")
    monkeypatch.setenv("OPENCTI_URL", "https://opencti.invalid")
    monkeypatch.setenv("OPENCTI_API_KEY", "mock-opencti")
    monkeypatch.setenv("OPENCTI_ENABLED", "true")
    service = build_threat_intelligence_service()

    assert service.enabled is True
    assert {provider.name for provider in service.providers} == {"abuseipdb", "virustotal", "otx", "opencti"}
    assert all(provider.api_key for provider in service.providers)
