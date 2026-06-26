# IntelliPatch

Automated CVE scanning and remediation for container images. Trivy scans Docker/Kubernetes images, a scikit-learn model prioritizes findings by exploitability rather than raw CVSS score, an LLM drafts remediation reports, and a CI/CD gate blocks deploys on unresolved critical CVEs.

## Planned architecture

```
Docker/Kubernetes images -> Trivy scan -> CVE findings
                                              |
                                              v
                                  ML-based CVSS/exploitability ranking
                                              |
                                              v
                                  LLM remediation report -> GitHub Actions deploy gate
```

## Planned stack

Trivy · scikit-learn · OpenAI API · GitHub Actions · Kubernetes + Docker · FastAPI · PostgreSQL

## Status

Planned — design complete, scaffolding in progress. Target: 1000+ images scanned, CI/CD gate blocking critical-severity deploys.
