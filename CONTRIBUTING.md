# Contributing to AIWall

Issues and pull requests are welcome. The `0.2.x` line is in a distribution freeze: bug fixes, docs, tests, and detection content are in scope. A new product feature should start as an issue.

The three public repos are one loop. Start in whichever repo you opened:

| Repo | You change | Good first issue |
|---|---|---|
| [AIWall](https://github.com/MohsenBahremani/AIWall) | Gateway, policies, audit schema | [#1](https://github.com/MohsenBahremani/AIWall/issues/1) |
| [AIWall-detections](https://github.com/MohsenBahremani/AIWall-detections) | Wazuh, Sigma, Loki, playbooks | [#1](https://github.com/MohsenBahremani/AIWall-detections/issues/1) |
| [AIWall-redteam](https://github.com/MohsenBahremani/AIWall-redteam) | Payloads and regression holds | [#1](https://github.com/MohsenBahremani/AIWall-redteam/issues/1) |

## Set up

Python 3.12.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check backend
pytest
```

See a block with no API key:

```bash
./scripts/capture-demo.sh
```

## Audit reasons

`reason` on `aiwall.audit.v1` is a closed vocabulary. CI rejects a new reason that is not added to the contract test and the detections sample corpus together. Do not rename an existing reason. SIEM rules match it.

## Sign-off

External contributions use a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. No CLA.

```text
git commit -s
```

## Security reports

Open a private GitHub security advisory on this repo. Do not file exploit details as a public issue. Payloads in AIWall-redteam are for a lab you control.
