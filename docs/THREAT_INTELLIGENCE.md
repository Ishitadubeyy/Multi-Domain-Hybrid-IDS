# Threat intelligence integration

The existing integration provides optional IP lookups through AbuseIPDB,
VirusTotal, AlienVault OTX, and OpenCTI. Provider responses are normalized
with provider names and availability/error information, IOC matches are
exact, and a shared in-memory TTL cache avoids duplicate requests during a
process lifetime.

## Configuration

Set `THREAT_INTEL_ENABLED=true` and only the credentials for providers you are
authorized to use:

```powershell
$env:ABUSEIPDB_API_KEY = "<your key>"
$env:VIRUSTOTAL_API_KEY = "<your key>"
$env:OTX_API_KEY = "<your key>"
$env:OPENCTI_URL = "https://your-opencti.example"
$env:OPENCTI_API_KEY = "<your key>"
$env:OPENCTI_ENABLED = "true"
$env:THREAT_INTEL_CACHE_TTL_SECONDS = "300"
$env:THREAT_INTEL_TIMEOUT_SECONDS = "10"
```

`.env.example` contains placeholders only and is not loaded automatically.
Keep real keys in the process environment or an approved secret store.

## Privacy and operational limits

The alert pipeline invokes providers only for valid globally routable IP
addresses, and each provider independently enforces the same restriction.
Private, loopback, link-local, reserved, and invalid values are not sent to
external providers; the alert records a lookup-policy skip rather than turning
the result into a clean verdict. Threat-intelligence lookups are disabled by
default.

The implemented provider adapters use request timeouts and report provider
failures as unavailable results. They do not currently implement provider-
specific rate-limit backoff or retries. The cache is process-local and
in-memory. Live lookups support IP addresses; domain, URL, and hash IOC
normalization/matching can consume supplied results but there are no live
provider adapters for those indicator types. URLhaus and ThreatFox are not
implemented.

An unavailable provider must not be interpreted as clean. `available=false`
and its error are retained in the normalized result. Alert severity remains
separate from provider reputation and model confidence.

## Validation status

Provider parsing, failure isolation, IOC matching, cache behavior, and
environment configuration are covered by mocked-response tests. No live
provider response was requested or fabricated; API keys and authorized
account status were not available for a live connectivity check.
