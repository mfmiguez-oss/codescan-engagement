# Benchmark targets

## Running one

A benchmark run is scored on true and false positives per test case, so it wants
a **narrower** run than a real engagement, not the same run with more turned on.

**Leave `--chains` and `--pocs` off.** Neither contributes anything a scorecard
reads: chains cost one call per service and PoCs one per critical finding, and a
case is scored the same whether or not a PoC was drafted for it. They are the
cheapest thing to cut and the only cut that costs no coverage at all.

**Use `--effort` where the model takes one.** It shortens the answer, and answer
length is what both spend and wall clock are made of. It is silently omitted for
families that reject the parameter — Haiku 4.5 and Sonnet 4.5 — so a Haiku
shakedown gets no benefit from it and a reportable Opus run gets most of one.

**Raise `--scenario-concurrency` only against a measured quota.** The scenario
phase is one call per scenario and hundreds of them, all independent, so it is
where wall clock lives. But a live BenchmarkPython run was throttled at ~156K
input tokens/minute while running strictly *sequentially*, because a cached
prompt prefix still counts against a per-minute quota even though it is nearly
free in money. Concurrency multiplies that. Find the resource's limit first.

**Report recall against what was routed, not the corpus.** Only 297 of
BenchmarkPython's 1,230 cases route at the current expert caps. Scoring against
all 1,230 blames the model for what the router never sent it.

## Targets

OWASP Benchmark (Java)
https://github.com/OWASP-Benchmark/BenchmarkJava

OWASP Benchmark (Python)
https://github.com/OWASP-Benchmark/BenchmarkPython

OWASP WebGoat (Java)
https://github.com/WebGoat/WebGoat

OWASP Juice Shop (Node.js)
https://github.com/juice-shop/juice-shop

Damn Vulnerable Web Application (PHP)
https://github.com/digininja/DVWA

Damn Vulnerable Node Application (Node.js)
https://github.com/appsecco/dvna

for Python
https://github.com/anxolerd/dvpwa

for Ruby RailsGoat
https://github.com/OWASP/railsgoat

for .NET
https://github.com/veeral-patel/VulnerableDotNet

CloudGoat (AWS)
https://github.com/RhinoSecurityLabs/cloudgoat

Terragoat (Terraform)
https://github.com/bridgecrewio/terragoat

OWASP ServerlessGoat
https://github.com/OWASP/Serverless-Goat

PoC‑in‑GitHub (nomi-sec)
https://github.com/nomi-sec/PoC-in-GitHub

trickest/cve
https://github.com/trickest/cve

DSVW (Damn Small Vulnerable Web)
https://github.com/stamparm/DSVW

Vulnado (Node.js)
https://github.com/cr0hn/vulnado
