import os
import openai
from google import genai
from google.genai import types

def fetch_available_models(provider: str, api_key: str) -> list:
    """Fetch dynamically listing of models from the provider's API."""
    models = []
    
    if provider == "gemini":
        client = genai.Client(api_key=api_key)
        # Using the new genai SDK methods
        for m in client.models.list():
            name = m.name.replace("models/", "")
            # Filter to include only text/chat generation models, skip vision/embedding specific ones if possible
            if "gemini" in name and "vision" not in name and "embedding" not in name:
                models.append({"id": name, "name": name.replace("-", " ").title()})
                
    elif provider == "deepseek":
        client = openai.OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        for m in client.models.list().data:
            models.append({"id": m.id, "name": m.id})
            
    elif provider == "openai":
        client = openai.OpenAI(api_key=api_key)
        for m in client.models.list().data:
            # Filter for GPT models only to skip audio/whisper/dall-e
            if "gpt" in m.id or "o1" in m.id or "o3" in m.id:
                models.append({"id": m.id, "name": m.id})
                
    else:
        raise ValueError(f"Unknown AI Provider: {provider}")
        
    # Deduplicate and sort
    seen = set()
    unique_models = []
    for m in models:
        if m["id"] not in seen:
            seen.add(m["id"])
            unique_models.append(m)
            
    # Sort alphabetically by ID descending to put newest up top usually
    return sorted(unique_models, key=lambda x: x["id"], reverse=True)

def build_reverser_prompt(decompiled_code: str, ioctl_code: str, language: str = "en") -> str:
    lang_instruction = ""
    if language == "zh":
        lang_instruction = "\nCRITICAL: You MUST write your detailed vulnerability analysis and reasoning strictly in Simplified Chinese (简体中文). However, keep technical terms like 'buffer overflow' or 'Use-After-Free' in English if appropriate."

    return f"""
You are a top-tier Windows kernel vulnerability researcher.
Analyze the following decompiled C code from a Windows kernel driver's IOCTL dispatch routine.
Pay close attention to the handling of IOCTL code: {ioctl_code}.

Look for:
- Missing ProbeForRead/ProbeForWrite (if METHOD_NEITHER is used)
- Buffer overflows (trusted user lengths in memcpy/memmove)
- Arbitrary memory write (Write-What-Where) primitives
- Use-After-Free or Double Free

Code:
```c
{decompiled_code}
```

Provide a brief, step-by-step root cause analysis if a vulnerability exists.{lang_instruction}

At the very end of your response, output exactly one of these two strings (on a new line):
[VULN_EXISTS=TRUE]
[VULN_EXISTS=FALSE]
"""

def build_exploiter_prompt(decompiled_code: str, device_name: str, ioctl_code: str, reverser_analysis: str, language: str = "en") -> str:
    lang_instruction = ""
    if language == "zh":
        lang_instruction = "Any explanation text outside of the code block MUST be written in Simplified Chinese (简体中文). However, the C++ code itself and its comments MUST remain in English."

    return f"""
You are a senior exploit developer.
Based on the following vulnerability analysis from the Reverser Agent, write a standalone C++ Proof-of-Concept (PoC) exploit for Windows.

Driver Device Name: {device_name}
Target IOCTL Code: {ioctl_code}

Reverser Analysis:
{reverser_analysis}

Decompiled Code Context:
```c
{decompiled_code}
```

Write a complete, compilable Windows C++ program (using <windows.h>, CreateFile, DeviceIoControl) that triggers this vulnerability.
If it's an arbitrary write, make it write `0x4141414141414141` to `0x4242424242424242` as a demonstration.
{lang_instruction}
Output ONLY the C++ code block. No markdown wrappers around the file, just the raw code.
"""

def call_llm(prompt: str, ai_conf: dict, api_key: str, temperature: float = 0.2) -> str:
    provider = ai_conf.get("provider", "gemini")
    model_name = ai_conf.get("model", "gemini-2.5-flash")
    
    if provider == "gemini":
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=temperature,
            ),
        )
        return response.text
        
    elif provider == "deepseek":
        client = openai.OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a senior Windows kernel vulnerability researcher and exploit developer."},
                {"role": "user", "content": prompt},
            ],
            stream=False,
            temperature=temperature
        )
        return response.choices[0].message.content
        
    elif provider == "openai":
        client = openai.OpenAI(api_key=api_key) # Defaults to api.openai.com
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a senior Windows kernel vulnerability researcher and exploit developer."},
                {"role": "user", "content": prompt},
            ],
            stream=False,
            temperature=temperature
        )
        return response.choices[0].message.content
    else:
        raise ValueError(f"Unknown AI Provider: {provider}")

def run_reverser_agent(decompiled_code: str, ioctl_code: str, language: str, ai_conf: dict, api_key: str) -> dict:
    prompt = build_reverser_prompt(decompiled_code, ioctl_code, language)
    analysis = call_llm(prompt, ai_conf, api_key, temperature=0.2)
    
    vuln_exists = "[VULN_EXISTS=TRUE]" in analysis
    # Clean the marker from the user-facing text
    clean_analysis = analysis.replace("[VULN_EXISTS=TRUE]", "").replace("[VULN_EXISTS=FALSE]", "").strip()
    
    return {
        "analysis": clean_analysis,
        "vuln_exists": vuln_exists
    }

def run_exploiter_agent(decompiled_code: str, device_name: str, ioctl_code: str, reverser_analysis: str, language: str, ai_conf: dict, api_key: str) -> str:
    prompt = build_exploiter_prompt(decompiled_code, device_name, ioctl_code, reverser_analysis, language)
    poc_code = call_llm(prompt, ai_conf, api_key, temperature=0.1)
    
    # Clean markdown if the LLM still wrapped it
    if poc_code.startswith("```cpp"):
        poc_code = poc_code[6:]
    elif poc_code.startswith("```c"):
        poc_code = poc_code[4:]
    if poc_code.endswith("```"):
        poc_code = poc_code[:-3]
        
    return poc_code.strip()
