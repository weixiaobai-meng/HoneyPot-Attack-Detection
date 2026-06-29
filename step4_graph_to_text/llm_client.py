"""LLM client used by the Step4 graph-to-text analysis layer."""

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from typing import Any, Dict, Mapping, Optional

import requests


DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_MAX_TOKENS = 2400
DEFAULT_TEMPERATURE = 0.2
DEFAULT_TIMEOUT_SECONDS = 75

SYSTEM_PROMPT = (
    "You are a senior network-security incident analyst assisting a graduate thesis. "
    "Use only the evidence in the user prompt. Do not invent IP addresses, alert counts, "
    "MITRE ATT&CK mappings, causal links, or remediation facts. If evidence is insufficient, "
    "say so explicitly. Return a structured Chinese Markdown report and clearly mark the "
    "content as LLM-assisted interpretation, not experimental ground truth."
)


@dataclass
class DeepSeekConfig:
    api_key: str
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    temperature: float = DEFAULT_TEMPERATURE
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    @property
    def configured(self) -> bool:
        return bool(self.api_key.strip())


def _env_int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = str(env.get(name, "")).strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def _env_float(env: Mapping[str, str], name: str, default: float, minimum: float, maximum: float) -> float:
    raw_value = str(env.get(name, "")).strip()
    if not raw_value:
        return default
    try:
        value = float(raw_value)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def load_deepseek_config(env: Optional[Mapping[str, str]] = None) -> DeepSeekConfig:
    env = env or os.environ
    return DeepSeekConfig(
        api_key=str(env.get("DEEPSEEK_API_KEY", "")).strip(),
        base_url=str(env.get("DEEPSEEK_BASE_URL", DEFAULT_BASE_URL)).strip() or DEFAULT_BASE_URL,
        model=str(env.get("DEEPSEEK_MODEL", DEFAULT_MODEL)).strip() or DEFAULT_MODEL,
        max_tokens=_env_int(env, "DEEPSEEK_MAX_TOKENS", DEFAULT_MAX_TOKENS, 256, 12000),
        temperature=_env_float(env, "DEEPSEEK_TEMPERATURE", DEFAULT_TEMPERATURE, 0.0, 1.5),
        timeout_seconds=_env_int(env, "DEEPSEEK_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS, 5, 300),
    )


def public_config(config: DeepSeekConfig) -> Dict[str, Any]:
    return {
        "provider": "deepseek",
        "configured": config.configured,
        "base_url": config.base_url.rstrip("/"),
        "model": config.model,
        "max_tokens": config.max_tokens,
        "temperature": config.temperature,
        "timeout_seconds": config.timeout_seconds,
    }


def _chat_completions_url(base_url: str) -> str:
    normalized = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _error_result(status: str, message: str, config: DeepSeekConfig, **extra: Any) -> Dict[str, Any]:
    meta = {
        **public_config(config),
        "status": status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **extra,
    }
    return {
        "ok": False,
        "status": status,
        "message": message,
        "content": "",
        "meta": meta,
    }


def generate_deepseek_report(prompt: str, config: Optional[DeepSeekConfig] = None) -> Dict[str, Any]:
    config = config or load_deepseek_config()
    prompt = str(prompt or "").strip()
    if not prompt:
        return _error_result("prompt_missing", "LLM prompt is empty; run Step1-Step4 analysis first.", config)
    if not config.configured:
        return _error_result(
            "llm_config_missing",
            "DEEPSEEK_API_KEY is not configured on the server process.",
            config,
        )

    url = _chat_completions_url(config.base_url)
    request_body = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "stream": False,
    }
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(url, headers=headers, json=request_body, timeout=config.timeout_seconds)
    except requests.Timeout:
        return _error_result("request_timeout", "DeepSeek API request timed out.", config, endpoint=url)
    except requests.RequestException as exc:
        return _error_result("request_failed", str(exc), config, endpoint=url)

    if response.status_code < 200 or response.status_code >= 300:
        return _error_result(
            "api_error",
            f"DeepSeek API returned HTTP {response.status_code}.",
            config,
            endpoint=url,
            status_code=response.status_code,
            response_text=response.text[:800],
        )

    try:
        payload = response.json()
    except ValueError:
        return _error_result("invalid_json", "DeepSeek API returned non-JSON response.", config, endpoint=url)

    choices = payload.get("choices") or []
    first_choice = choices[0] if choices else {}
    content = ((first_choice.get("message") or {}).get("content") or "").strip()
    if not content:
        return _error_result("empty_response", "DeepSeek API returned an empty message.", config, endpoint=url)

    meta = {
        **public_config(config),
        "status": "success",
        "endpoint": url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finish_reason": first_choice.get("finish_reason"),
        "usage": payload.get("usage") or {},
    }
    return {
        "ok": True,
        "status": "success",
        "message": "success",
        "content": content,
        "meta": meta,
    }
