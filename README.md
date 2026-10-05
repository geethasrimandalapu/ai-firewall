# AI Firewall

**A security and governance gateway for LLMs and AI agents, built with Java 21 and Spring Boot 3.**

![CI](https://github.com/geethasrimandalapu/ai-firewall/actions/workflows/ci.yml/badge.svg)
![Java 21](https://img.shields.io/badge/Java-21-orange)
![Spring Boot 3](https://img.shields.io/badge/Spring%20Boot-3.4-brightgreen)
![Tests](https://img.shields.io/badge/tests-22%20passing-success)

![AI Firewall dashboard](docs/dashboard.png)

*The live console: a prompt-injection attack blocked (risk 100/100), customer email and card number redacted before reaching the model, and a $900 agent refund held for human approval.*

Companies want their teams and AI agents to use models like GPT and Claude, but they are afraid of three things:

1. **Data leaks:** employees paste customer data, card numbers and API keys into AI chats.
2. **Prompt injection:** attackers hide instructions in emails, web pages or documents that hijack the AI.
3. **Rogue agents:** AI agents can call real tools (refunds, deletes, deploys) with nobody controlling what they may do.

AI Firewall sits between your apps and any AI model and fixes all three, with a full audit trail.

```
                   ┌──────────────────────── AI Firewall ────────────────────────┐
  App / Agent ───► │ 1. Injection detector ─► 2. PII redactor ─► 3. Model call   │ ───► OpenAI / Azure /
  (OpenAI SDK,     │      block if risk ≥ 50    [EMAIL_1] tokens      restore    │      Ollama / any
   Spring AI,      │                                                 values      │      OpenAI-compatible
   LangChain)      │ 4. Tool policy engine (zero-trust)  5. Audit log + cost     │
                   └──────────────────────────────────┬──────────────────────────┘
                                                      ▼
                                          Live security dashboard
```

## Features

| Feature | What it does |
|---|---|
| **Drop-in OpenAI-compatible API** | Apps only change their base URL to `http://localhost:8080/v1`. No code changes. |
| **Reversible PII redaction** | Emails, phones, card numbers (Luhn-checked), SSNs, API keys, JWTs, private keys and IPs become tokens like `[EMAIL_1]` before leaving the company, then real values are restored in the answer. The AI provider never sees them. |
| **Prompt-injection defense** | Weighted rules for 11 attack families, plus unicode normalisation, zero-width character detection, leetspeak undoing and decoding of hidden Base64 payloads. |
| **Indirect injection defense** | Also scans `tool` messages (web pages, emails, files an agent read), where most real attacks hide. |
| **Agent tool policies** | Per-agent allow/deny lists and argument limits, e.g. refunds over $100 need a human (`REQUIRE_APPROVAL`). Unknown agents and tools are denied by default. |
| **Audit log + cost tracking** | Every decision is stored with risk score, data types found, tokens, cost and latency. Secrets are never stored. |
| **Live dashboard** | Playground with one-click attack demos, tool-call tester and real-time audit feed. |

## Quick start

Requirements: Java 21 and Maven (or Docker).

```bash
# Runs with a built-in mock model, no API key needed
mvn spring-boot:run
# open http://localhost:8080
```

Use a real model (any OpenAI-compatible API):

```bash
export LLM_API_KEY=your-key
export LLM_MODEL=gpt-4o-mini           # optional
export LLM_BASE_URL=https://api.openai.com/v1   # or http://localhost:11434/v1 for Ollama
mvn spring-boot:run
```

With Docker:

```bash
docker compose up --build
```

Run tests:

```bash
mvn test
```

## API

### Chat through the firewall (OpenAI format)

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" -H "X-User-Id: priya" \
  -d '{"messages":[{"role":"user","content":"Email bob@acme.com about card 4111 1111 1111 1111"}]}'
```

The response is a normal OpenAI response plus an `x_firewall` block showing the risk score and exactly what the model saw. Attacks return `403` with `prompt_injection_blocked`.

Works with existing SDKs, for example Python: `OpenAI(base_url="http://localhost:8080/v1")`.

### Ask before an agent runs a tool

```bash
curl http://localhost:8080/v1/tools/authorize \
  -H "Content-Type: application/json" \
  -d '{"agentId":"support-bot","tool":"issue_refund","arguments":{"amount":900}}'
# {"decision":"REQUIRE_APPROVAL","reason":"amount=900 exceeds limit 100.0","argumentRisk":0}
```

Policies live in `application.yml` under `firewall.agents`.

### Other endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/scan` | Check any text for PII and injection without calling a model |
| GET | `/api/audit/events` | Last 100 audit events |
| GET | `/api/audit/stats` | Totals: blocked, redacted, tokens, cost |
| GET | `/api/policies` | Active agent policies |
| GET | `/actuator/health` | Health check |

## Project structure

```
src/main/java/com/aifirewall
├── core/       PiiRedactor, InjectionDetector   (framework-free, unit tested)
├── policy/     PolicyEngine                      (zero-trust tool permissions)
├── gateway/    Chat proxy, tool authorization, scan API
├── llm/        Upstream client + offline mock model
├── audit/      JPA entity, repository, stats API
└── config/     Typed configuration
```

## Design decisions

- **Core logic has no Spring dependencies,** so it is fast to unit test and could be reused as a library.
- **Default deny** for agents and tools, following zero-trust security.
- **Reversible tokens** instead of `***` masking, so the model can still reason ("reply to [EMAIL_1]") and the user still gets a useful answer.
- **OpenAI-compatible API** so adoption needs no code changes.

## Roadmap

- [ ] Streaming (SSE) responses
- [ ] LLM-based injection classifier as a second opinion for borderline scores
- [ ] Human approval queue for `REQUIRE_APPROVAL` tool calls
- [ ] Per-team budgets and rate limits
- [ ] Spring Security with API keys per app, PostgreSQL for production
- [ ] MCP (Model Context Protocol) proxy mode for agent tool servers

## Limitations

Rule-based detection catches known attack patterns but not every novel one; it is one layer of defense, not a guarantee. Cost figures are estimates based on the configured prices.

## Author

Built by **Geetha Sri Mandalapu**, Computer Science graduate (December 2026).
