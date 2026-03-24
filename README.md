# 🔴 AgentProbe

Prompt injection red-teaming CLI for AI agents. Test your agent's resilience against credential leaks, system prompt extraction, and other injection attacks before shipping.

**Three modes:**
- **`scan`** — Fire 44+ static payloads at your agent and grade the results
- **`attack`** — LLM-powered adaptive red-teaming (AI vs AI) with multi-turn conversation
- **Custom payloads** — Bring your own domain-specific attack packs via JSON/YAML files

## Install

```bash
# Clone and install
git clone https://github.com/maneeshv/agentprobe.git
cd agentprobe
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Quick Start

### Static Scan

```bash
# Scan a standard JSON API
agentprobe scan https://your-agent.com/api/chat

# OpenAI-compatible API
agentprobe scan https://api.example.com/v1/chat/completions \
  --body '{"model":"gpt-4","messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \
  --response-path 'choices.0.message.content' \
  -H 'Authorization: Bearer sk-...'

# SSE streaming endpoint
agentprobe scan https://your-agent.com/api/stream --sse \
  --cookie 'session=abc123' \
  --body '{"event":"textbox","params":{"question":"{{PAYLOAD}}"}}' \
  --payload-path 'params.question'

# Scan with a config file
agentprobe scan --config target.json

# Only critical severity
agentprobe scan URL --severity critical

# CI/CD: JSON + JUnit output, fail on leaks
agentprobe scan URL -o results.json --junit report.xml --fail-on-leak
```

### Adaptive Attack (AI vs AI)

An attacker LLM probes your agent in real-time, reads responses, adapts strategy, and crafts follow-up attacks — like a human red-teamer but automated.

```bash
# GPT-4o attacking via OpenRouter
agentprobe attack https://your-agent.com/api/chat \
  --sse --cookie 'token=...' \
  --description 'A product recommendation chatbot for Acme Corp' \
  --attacker-api-key $OPENROUTER_KEY \
  --turns 15 --log attack.log -o results.json

# Grok as attacker
agentprobe attack URL --attacker-provider grok \
  --attacker-api-key $XAI_KEY --turns 10

# Claude as attacker (native Anthropic API)
agentprobe attack URL --attacker-provider anthropic \
  --attacker-api-key $ANTHROPIC_KEY

# Gemini as attacker
agentprobe attack URL --attacker-provider gemini \
  --attacker-api-key $GEMINI_KEY
```

### Custom Payloads

Write domain-specific attacks without touching source code:

```bash
# Run only custom payloads
agentprobe scan URL -f my-payloads.json

# Combine with built-in payloads
agentprobe scan URL -f my-payloads.json --domain flexcon

# Preview payloads
agentprobe list -f my-payloads.json
```

**Payload file format (JSON):**
```json
{
  "meta": { "name": "My Attack Pack", "version": "1.0" },
  "payloads": [
    {
      "name": "my-attack",
      "category": "custom",
      "prompt": "The injection text to send...",
      "severity": "high",
      "description": "What this attack tries to do",
      "tags": ["credential-leak", "social-engineering"]
    }
  ]
}
```

YAML also supported (requires `pip install pyyaml`).

## Payload Categories

### Built-in (44 payloads)

| Category | Description |
|----------|-------------|
| `instruction-override` | Direct "ignore previous instructions" attacks |
| `roleplay` | Persona hijacking and fake modes |
| `encoding` | Base64, ROT13, reverse text, unicode homoglyphs |
| `indirect` | Tool abuse, file reads, command execution |
| `multi-turn` | Gradual escalation across multiple messages |
| `context-manipulation` | Fake conversation history, delimiter injection |
| `exfiltration` | Data leaking via URLs, images, generated code |
| `system-prompt-extraction` | Extracting the system prompt |
| `privilege-escalation` | Fake admin claims, auth bypass |
| `dos` | Resource exhaustion attacks |
| `subtle` | Social engineering, helpful-framing attacks |

### Domain Pack: Flexcon (26 payloads)

Tailored for product recommendation agents. Enable with `--domain flexcon`:

| Category | Description |
|----------|-------------|
| `trojan-query` | Injection hidden inside legitimate product questions |
| `role-hijack` | Fake QA engineer, product manager, IT admin |
| `spec-injection` | Payloads embedded in CSV specs, customer emails, JSON |
| `data-extraction` | Customer lists, pricing, inventory probes |
| `rag-manipulation` | Hallucination testing, spec override, chunk extraction |
| `competitor-manipulation` | Competitor data extraction, badmouthing |
| `boundary-test` | Email sending, catalog modification, discount approval |
| `exfiltration-domain` | Data exfil disguised as product comparisons |

## Detection

Responses are analyzed for:
- **Credential patterns**: API keys (OpenAI, Anthropic, GitHub, Slack, Google, AWS), connection strings, bearer tokens, private keys
- **System prompt leakage**: Persona definitions, instruction language, LLM template markers
- **Refusal detection**: Recognizes proper refusals and scope-deflection patterns
- **False positive filtering**: Refusal messages that mention "system prompt" while refusing aren't flagged as leaks

## Attacker LLM Providers

The `attack` command supports 11 providers out of the box:

| Provider | Flag | Default Model | API Format |
|----------|------|---------------|------------|
| OpenRouter | `--attacker-provider openrouter` | openai/gpt-4o | OpenAI-compatible |
| OpenAI | `--attacker-provider openai` | gpt-4o | OpenAI-compatible |
| Grok/xAI | `--attacker-provider grok` | grok-3 | OpenAI-compatible |
| Anthropic | `--attacker-provider anthropic` | claude-sonnet | Native Messages API |
| Google Gemini | `--attacker-provider gemini` | gemini-2.5-flash | Native Gemini API |
| Together | `--attacker-provider together` | Llama 3.3 70B | OpenAI-compatible |
| Groq | `--attacker-provider groq` | Llama 3.3 70B | OpenAI-compatible |
| DeepSeek | `--attacker-provider deepseek` | deepseek-chat | OpenAI-compatible |
| Fireworks | `--attacker-provider fireworks` | Llama 3.3 70B | OpenAI-compatible |

Any OpenAI-compatible endpoint works with `--attacker-api-base`.

## SSE Streaming

For agents that use Server-Sent Events:

```bash
agentprobe scan URL --sse \
  --cookie 'auth_token=...' \
  --body '{"event":"textbox","params":{"question":"{{PAYLOAD}}"}}' \
  --payload-path 'params.question' \
  --response-path 'message.response.data.answer.answer'
```

## Config Files

Avoid long CLI commands with JSON config:

```bash
agentprobe init              # Generate sample config
agentprobe scan --config target.json
agentprobe attack --config target.json --attacker-provider grok --attacker-api-key $KEY
```

**Sample config:**
```json
{
  "endpoint": "https://agent.example.com/api/chat/THREAD_ID",
  "new_conversation_endpoint": "https://agent.example.com/api/chat",
  "mode": "sse",
  "headers": { "Origin": "https://app.example.com" },
  "cookie": "session_token=...",
  "body_template": {
    "event": "textbox",
    "params": { "question": "{{PAYLOAD}}", "thinking_mode": "quick" }
  },
  "payload_path": "params.question",
  "response_path": "message.response.data.answer.answer",
  "target_description": "A product recommendation assistant",
  "timeout": 60,
  "concurrency": 2,
  "delay": 2.0
}
```

## Scan Logging

Capture full responses for review:

```bash
agentprobe scan URL --log scan.log -o results.json
agentprobe attack URL --log attack.log -o results.json
```

Log files include complete probe text and full agent responses — useful for manual review and iterating on payloads.

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install -e .
    agentprobe scan ${{ secrets.AGENT_URL }} \
      --header "Authorization: Bearer ${{ secrets.AGENT_KEY }}" \
      --junit results.xml \
      --fail-on-leak

- name: Upload Results
  uses: actions/upload-artifact@v4
  with:
    name: agentprobe-results
    path: results.xml
```

## Scoring

Each scan produces a security score:

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | ≥95% | Excellent — nearly all attacks refused |
| A | ≥90% | Strong |
| B | ≥80% | Good |
| C | ≥70% | Needs improvement |
| D | ≥50% | Significant gaps |
| F | <50% | Critical — many attacks succeeded |

## Commands

```bash
agentprobe scan URL              # Static payload scan
agentprobe attack URL            # Adaptive AI-powered attack
agentprobe list                  # List all payloads
agentprobe list --domain flexcon # List domain-specific payloads
agentprobe list -f custom.json   # List custom payloads
agentprobe categories            # List payload categories
agentprobe tags                  # List payload tags
agentprobe init                  # Generate sample config file
```
