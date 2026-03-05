import os
import json
import asyncio
import subprocess
import tempfile
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

import agents

app = FastAPI(title="Cthaeh AVR Backend")

# We allow CORS in case the UI is run separately during dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration - adjust these or use environment variables
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", r"D:\ghidra_12.0.3_PUBLIC")

# Gemini API configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
AVAILABLE_MODELS = {
    "gemini": "gemini-2.5-flash",
    "gemini-pro": "gemini-2.5-pro"
}

class AnalyzeRequest(BaseModel):
    driver_path: str
    ioctl_code: str = "Unknown" # Optional, if the user highlights a specific one
    language: str = "en" # "en" or "zh"
    ai_config: dict = {} # Phase 5: Pass the provider, model, and apiKey

class AnalyzeResponse(BaseModel):
    status: str
    reverser_analysis: str = ""
    vuln_exists: bool = False
    poc_code: str = ""
    error: str = ""

class CompileRequest(BaseModel):
    poc_code: str
    ioctl_code: str
    ai_config: Optional[dict] = None
    language: str = "en"

class CompileResponse(BaseModel):
    status: str
    exe_path: str = ""
    compiler_output: str = ""
    fixed_poc_code: str = ""
    error: str = ""

class RunPocRequest(BaseModel):
    exe_path: str

class RunPocResponse(BaseModel):
    status: str
    output: str = ""
    error: str = ""

class ReportRequest(BaseModel):
    driver_name: str
    driver_path: str
    finding_check: str
    ioctl_code: str
    reverser_analysis: str
    poc_code: str
    ai_config: Optional[dict] = None
    language: str = "en"

class ReportResponse(BaseModel):
    status: str
    report_markdown: str = ""
    error: str = ""

@app.get("/api/models")
async def get_models(provider: str = Query("gemini"), api_key: Optional[str] = None):
    # Fallback to env var if UI didn't provide one
    if not api_key:
        if provider == "gemini":
            api_key = GEMINI_API_KEY
        else:
            api_key = os.environ.get("OPENAI_API_KEY") 

    if not api_key:
        return {"status": "error", "error": f"Missing API Key for provider '{provider}'. Please configure it in settings."}

    try:
        models = agents.fetch_available_models(provider, api_key)
        return {"status": "success", "models": models}
    except Exception as e:
        return {"status": "error", "error": str(e)}

class RescanResponse(BaseModel):
    status: str
    message: str = ""
    error: str = ""

@app.post("/api/rescan", response_model=RescanResponse)
async def rescan_device():
    """Trigger a new extraction and triage of system drivers."""
    try:
        # Run triage script synchronously for now so the UI can just await the fetch
        # and reload the page when it's completely done.
        process = await asyncio.create_subprocess_exec(
            "python", "run_triage.py",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            return RescanResponse(status="error", error=f"Triage failed with code {process.returncode}:\n{stderr.decode('utf-8', errors='ignore')}")
            
        return RescanResponse(status="success", message="Device drivers rescan completed successfully.")
    except Exception as e:
        return RescanResponse(status="error", error=str(e))

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_driver(req: AnalyzeRequest):
    # Retrieve AI configuration
    ai_conf = req.ai_config or {}
    api_key = ai_conf.get("apiKey", "").strip()
    provider = ai_conf.get("provider", "gemini")
    
    # Fallback to env var if UI didn't provide one
    if not api_key:
        if provider == "gemini":
            api_key = GEMINI_API_KEY
        else:
            api_key = os.environ.get("OPENAI_API_KEY") 

    if not api_key:
        return AnalyzeResponse(status="error", error=f"Missing API Key for provider '{provider}'. Please configure it in settings.")
        
    driver_path = req.driver_path
    if driver_path.startswith("/") and len(driver_path) > 2 and driver_path[2] == ":":
        driver_path = driver_path[1:]
    driver_path = os.path.normpath(driver_path)

    if not os.path.exists(driver_path):
        return AnalyzeResponse(status="error", error=f"Driver file not found: {req.driver_path} (Resolved: {driver_path})")
    
    # Step 1: Extract Decompiled Code using Ghidra Headless
    print(f"[*] Starting extraction for {driver_path} (IOCTL: {req.ioctl_code})...")
    
    # Create a completely unique temp directory for this specific extraction job
    # to prevent collisions when 'Analyze All' hits the backend concurrently.
    job_id = os.urandom(4).hex()
    safe_ioctl = req.ioctl_code.replace("0x", "")
    d_filename = os.path.basename(driver_path)
    job_dir = os.path.join(tempfile.gettempdir(), f"cthaeh_job_{d_filename}_{safe_ioctl}_{job_id}")
    os.makedirs(job_dir, exist_ok=True)
    
    output_c_file = os.path.join(job_dir, f"{d_filename}_decompiled.c")
    
    # We will build out ghidra_scripts/extract_ioctl.py next
    script_path = os.path.join(os.path.dirname(__file__), "ghidra_scripts", "extract_ioctl.py")
    analyze_headless_bat = os.path.join(GHIDRA_HOME, "support", "analyzeHeadless.bat")
    
    project_dir = os.path.join(job_dir, "ghidra_tmp_proj")
    os.makedirs(project_dir, exist_ok=True)
    
    cmd = [
        analyze_headless_bat,
        project_dir,
        "TempProject",
        "-import", driver_path,
        "-overwrite",
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path), output_c_file, req.ioctl_code
    ]
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0 and process.returncode != 128:  # 128 is thrown if script exits cleanly but project doesn't save
        print("Ghidra Error:\n", stderr.decode('utf-8', errors='ignore'))
        return AnalyzeResponse(status="error", error="Failed to extract decompiled code via Ghidra.")
        
    if not os.path.exists(output_c_file):
        return AnalyzeResponse(status="error", error="Ghidra succeeded but no C code was produced.")
        
    with open(output_c_file, 'r', encoding='utf-8', errors='ignore') as f:
        decompiled_code = f.read()

    device_name = f"\\\\.\\{d_filename.replace('.sys', '')}" # Fallback heuristic
        
    # Step 2: Agent 1 - Reverser
    print(f"[*] Triggering Reverser Agent on {len(decompiled_code)} bytes of decompiled code...")
    try:
        rev_res = agents.run_reverser_agent(decompiled_code, req.ioctl_code, req.language, ai_conf, api_key)
    except Exception as e:
        return AnalyzeResponse(status="error", error=f"Reverser Agent failed: {str(e)}")
        
    if not rev_res["vuln_exists"]:
        return AnalyzeResponse(
            status="success", 
            reverser_analysis=rev_res["analysis"], 
            vuln_exists=False,
            poc_code=""
        )
        
    # Step 3: Agent 2 - Exploiter
    print("[*] Vulnerability confirmed by Agent! Triggering Exploiter Agent for PoC generation...")
    try:
        poc = agents.run_exploiter_agent(decompiled_code, device_name, req.ioctl_code, rev_res["analysis"], req.language, ai_conf, api_key)
    except Exception as e:
         return AnalyzeResponse(status="success_partial", reverser_analysis=rev_res["analysis"], vuln_exists=True, poc_code=f"Exploiter Agent failed to generate PoC: {str(e)}")

    return AnalyzeResponse(
        status="success",
        reverser_analysis=rev_res["analysis"],
        vuln_exists=True,
        poc_code=poc
    )

@app.post("/api/compile", response_model=CompileResponse)
async def compile_poc(req: CompileRequest):
    ai_conf = req.ai_config or {}
    api_key = ai_conf.get("apiKey", "").strip()
    
    try:
        res = agents.run_compiler_agent(req.poc_code, req.ioctl_code, req.language, ai_conf, api_key)
        return CompileResponse(
            status="success" if res["success"] else "error",
            exe_path=res.get("exe_path", ""),
            compiler_output=res.get("compiler_output", ""),
            fixed_poc_code=res.get("fixed_poc_code", req.poc_code),
            error=res.get("error", "")
        )
    except Exception as e:
        return CompileResponse(status="error", error=f"Compiler Agent blocked: {str(e)}")

@app.post("/api/run_poc", response_model=RunPocResponse)
async def run_poc(req: RunPocRequest):
    if not os.path.exists(req.exe_path):
        return RunPocResponse(status="error", error=f"Executable not found: {req.exe_path}. Did compilation fail?")
        
    try:
        # Warning: Direct execution of PoC on the host system.
        process = await asyncio.create_subprocess_exec(
            req.exe_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        # Give it a max timeout of 10 seconds to avoid hung PoCs
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10.0)
        
        output = stdout.decode('utf-8', errors='ignore') + "\n" + stderr.decode('utf-8', errors='ignore')
        return RunPocResponse(status="success", output=output)
    except asyncio.TimeoutError:
        process.kill()
        return RunPocResponse(status="error", error="Execution timed out after 10 seconds. Process killed.")
    except Exception as e:
        return RunPocResponse(status="error", error=f"Failed to execute PoC: {str(e)}")

@app.post("/api/report", response_model=ReportResponse)
async def generate_report(req: ReportRequest):
    ai_conf = req.ai_config or {}
    api_key = ai_conf.get("apiKey", "").strip()
    
    try:
        report = agents.run_reporter_agent(
            req.driver_name,
            req.driver_path,
            req.finding_check,
            req.ioctl_code,
            req.reverser_analysis,
            req.poc_code,
            req.language,
            ai_conf,
            api_key
        )
        return ReportResponse(status="success", report_markdown=report)
    except Exception as e:
        return ReportResponse(status="error", error=str(e))

@app.get("/triage_results.json")
async def get_triage_results():
    file_path = "triage_results.json"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="triage_results.json not found")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

# Mount the static web_ui directory to the root /
app.mount("/", StaticFiles(directory="web_ui", html=True), name="web_ui")
