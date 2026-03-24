# 🔴 AgentProbe

Prompt injection red-teaming CLI for AI agents. Test your agent's resilience against credential leaks, system prompt extraction, and other injection attacks before shipping.

## Install

```bash
pip install -e .
```

## Quick Start

```bash
# Scan an agent endpoint
agentprobe scan https://your-agent.com/api/chat

# OpenAI-compatible API
agentprobe scan https://api.example.com/v1/chat/completions \
  --body '{"model":"gpt-4","messages":[{"role":"user","content":"{{PAYLOAD}}"}]}' \
  --response-path 'choices.0.message.content' \
  --header 'Authorization: Bearer sk-...'

# Only critical-severity attacks
agentprobe scan https://your-agent.com/api/chat --severity critical

# Specific attack category
agentprobe scan https://your-agent.com/api/chat --category exfiltration

# JSON output for CI/CD
agentprobe scan https://your-agent.com/api/chat --output-json results.json --fail-on-leak

# JUnit XML for test runners
agentprobe scan https://your-agent.com/api/chat --junit report.xml --fail-on-leak
```

## Payload Categories

| Category | Description |
|----------|-------------|
| `instruction-override` | Direct "ignore previous instructions" attacks |
| `roleplay` | Persona hijacking and fake modes |
| `encoding` | Base64, ROT13, reverse text, unicode tricks |
| `indirect` | Tool abuse, file reads, command execution |
| `multi-turn` | Gradual escalation across multiple messages |
| `context-manipulation` | Fake conversation history, delimiter injection |
| `exfiltration` | Data leaking via URLs, images, generated code |
| `system-prompt-extraction` | Extracting the system prompt |
| `privilege-escalation` | Fake admin claims, auth bypass |
| `dos` | Resource exhaustion attacks |
| `subtle` | Social engineering, helpful-framing attacks |

## Detection

AgentProbe checks responses for:
- **Credential patterns**: API keys (OpenAI, Anthropic, GitHub, Slack, Google, AWS), connection strings, bearer tokens, private keys
- **System prompt leakage**: Persona definitions, instruction language, LLM template markers
- **Refusal detection**: Recognizes when agents properly refuse injection attempts

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install agentprobe
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

## Commands

```bash
agentprobe list                  # List all payloads
agentprobe list --category encoding  # Filter by category
agentprobe list --verbose        # Show full payload details
agentprobe categories            # List categories
agentprobe tags                  # List tags
```

## Custom Body Templates

Use `{{PAYLOAD}}` as the placeholder in your body template:

```bash
# Simple message
--body '{"message": "{{PAYLOAD}}"}'

# OpenAI format
--body '{"model":"gpt-4","messages":[{"role":"user","content":"{{PAYLOAD}}"}]}'

# Custom format
--body '{"input": {"text": "{{PAYLOAD}}"}, "config": {"stream": false}}'
```

## Response Path

Extract the response text from JSON using dot notation:

```bash
--response-path 'choices.0.message.content'  # OpenAI
--response-path 'response'                    # Simple
--response-path 'data.output.text'            # Custom
```
