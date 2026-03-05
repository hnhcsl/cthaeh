import os
from google import genai
from google.genai import types

def build_reverser_prompt(decompiled_code: str, ioctl_code: str) -> str:
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

Provide a brief, step-by-step root cause analysis if a vulnerability exists.
At the very end of your response, output exactly one of these two strings (on a new line):
[VULN_EXISTS=TRUE]
[VULN_EXISTS=FALSE]
"""

def build_exploiter_prompt(decompiled_code: str, device_name: str, ioctl_code: str, reverser_analysis: str) -> str:
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
Output ONLY the C++ code block. No markdown wrappers around the file, just the raw code.
"""

def run_reverser_agent(api_key: str, model_name: str, decompiled_code: str, ioctl_code: str) -> dict:
    client = genai.Client(api_key=api_key)
    prompt = build_reverser_prompt(decompiled_code, ioctl_code)
    
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
        ),
    )
    
    analysis = response.text
    vuln_exists = "[VULN_EXISTS=TRUE]" in analysis
    
    # Clean the marker from the user-facing text
    clean_analysis = analysis.replace("[VULN_EXISTS=TRUE]", "").replace("[VULN_EXISTS=FALSE]", "").strip()
    
    return {
        "analysis": clean_analysis,
        "vuln_exists": vuln_exists
    }

def run_exploiter_agent(api_key: str, model_name: str, decompiled_code: str, device_name: str, ioctl_code: str, reverser_analysis: str) -> str:
    client = genai.Client(api_key=api_key)
    prompt = build_exploiter_prompt(decompiled_code, device_name, ioctl_code, reverser_analysis)
    
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
        ),
    )
    
    poc_code = response.text
    # Clean markdown if the LLM still wrapped it
    if poc_code.startswith("```cpp"):
        poc_code = poc_code[6:]
    elif poc_code.startswith("```c"):
        poc_code = poc_code[4:]
    if poc_code.endswith("```"):
        poc_code = poc_code[:-3]
        
    return poc_code.strip()
