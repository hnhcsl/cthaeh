import os
import openai
import subprocess
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

def try_compile(source_code: str, exe_name: str) -> tuple[bool, str]:
    with open("temp_poc.cpp", "w", encoding='utf-8') as f:
        f.write(source_code)
    try:
        # Try MSVC first
        res = subprocess.run(["cl.exe", "temp_poc.cpp", "/EHsc", "/Fe"+exe_name], capture_output=True, text=True, errors='ignore')
        if res.returncode == 0:
            return True, "Compiled successfully with cl.exe\n" + res.stdout
        err_cl = res.stdout + "\n" + res.stderr
    except FileNotFoundError:
        err_cl = "cl.exe not found in PATH."
        
    try:
        # Try g++ next
        res = subprocess.run(["g++", "temp_poc.cpp", "-o", exe_name, "-lntdll"], capture_output=True, text=True, errors='ignore')
        if res.returncode == 0:
            return True, "Compiled successfully with g++\n" + res.stdout
        err_gpp = res.stderr + "\n" + res.stdout
    except FileNotFoundError:
        err_gpp = "g++ not found in PATH."
        
    return False, f"MSVC Error:\n{err_cl}\n\nG++ Error:\n{err_gpp}\n\nPlease fix the compilation errors."

def run_compiler_agent(poc_code: str, ioctl_code: str, language: str, ai_conf: dict, api_key: str) -> dict:
    exe_name = f"poc_{ioctl_code.replace('0x', '')}.exe"
    current_code = poc_code
    
    for attempt in range(3):
        success, output = try_compile(current_code, exe_name)
        if success:
            return {"success": True, "exe_path": exe_name, "compiler_output": output, "fixed_poc_code": current_code}
            
        prompt = f"The following Windows C++ exploit PoC failed to compile.\n\nCompiler Output:\n{output}\n\nPoC Code:\n```cpp\n{current_code}\n```\n\nPlease fix the compilation errors. Output ONLY the raw fixed C++ code, no markdown wrappers, no explanations. Make sure it includes necessary headers like <windows.h>, <iostream>, and properly links or dynamically loads functions like NtQuerySystemInformation if needed."
        
        fixed_code = call_llm(prompt, ai_conf, api_key, temperature=0.1)
        
        if fixed_code.startswith("```cpp"):
            fixed_code = fixed_code[6:]
        elif fixed_code.startswith("```c"):
            fixed_code = fixed_code[4:]
        if fixed_code.endswith("```"):
            fixed_code = fixed_code[:-3]
        current_code = fixed_code.strip()
        
    return {"success": False, "exe_path": "", "compiler_output": "Failed to fix after 3 attempts.\nLast error:\n" + output, "error": "Max compilation attempts reached.", "fixed_poc_code": current_code}

def run_reporter_agent(driver_name: str, driver_path: str, finding_check: str, ioctl_code: str, reverser_analysis: str, poc_code: str, language: str, ai_conf: dict, api_key: str) -> str:
    instructions = ""
    if language == "zh":
        instructions = "Please output the final vulnerability disclosure report in professional Chinese."
        
    prompt = f"""You are a professional security researcher writing a vulnerability disclosure report for a vendor PSIRT.
    
Driver Name: {driver_name}
Target Path: {driver_path}
Vulnerability Type: {finding_check}
Trigger IOCTL: {ioctl_code}

Reverser Analysis:
{reverser_analysis}

Working Proof-of-Concept:
```cpp
{poc_code}
```

Write a formal security advisory report in Markdown format. It should include:
- Title
- Description / Impact
- Vulnerability Details (Root Cause Analysis based on Reverser Analysis)
- Reproduction Steps (using the provided PoC)
- Suggested Remediation

{instructions}
"""
    return call_llm(prompt, ai_conf, api_key, temperature=0.3)
