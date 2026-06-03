import httpx
from src.config import LLM_URL

MAX_PREDICT_TOKENS = 180


async def complete(prompt: str, temperature: float = 0.2, max_tokens: int = 320) -> str:
    wrapped = f"<|user|>\n{prompt}<|end|>\n<|assistant|>\n"
    n_predict = min(max_tokens, MAX_PREDICT_TOKENS)
    async with httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=5.0)) as client:
        resp = await client.post(
            f"{LLM_URL}/completion",
            json={
                "prompt": wrapped,
                "temperature": temperature,
                "n_predict": n_predict,
                "stop": ["<|end|>", "<|user|>", "<|assistant|>"],
            },
        )
        resp.raise_for_status()
        return resp.json()["content"].replace("<|assistant|>", "").strip()
