# Advanced BB Toolkit

An upgraded, highly scalable, and automated bug bounty toolkit designed for modern web application penetration testing.

## Features

- **Advanced Recon**: ASN mapping, Cloud asset discovery (S3, Azure, GCP).
- **API Security**: OpenAPI/Swagger parsing, hidden parameter discovery.
- **WAF Evasion**: Automated header rotation and smuggling tests.
- **Continuous Monitoring**: Diff-based alerting for new attack surfaces.

## Structure

- `/recon` - Asset discovery and cloud hunting.
- `/api_sec` - API contract mapping and fuzzing.
- `/evasion` - WAF bypass and payload mutation.
- `/continuous` - Cron jobs and diff monitors.