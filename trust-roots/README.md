# Trust roots

| file | channel | status |
|---|---|---|
| `rolling.pub` | rolling | **provisional** — generated 2026-08-07 for rolling-channel dogfooding; revocable at any time; makes no qualification promise |

The qualified-channel root does not exist yet: it is created by the root
ceremony (the v1.0 gate), with custody and rotation decided there — see
DD-009. The rolling root's secret half lives only in the repository secret
`VARVE_ROLLING_KEY`; the machine that generated it destroyed its copy after
provisioning.

Use: `export VARVE_TRUST_ROOT=/path/to/trust-roots/rolling.pub`
