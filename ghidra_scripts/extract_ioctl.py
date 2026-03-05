# Extract the decompiled C code of the IOCTL dispatch routine.
# @category AVR
# @runtime Jython

import sys
import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def get_args():
    args = getScriptArgs()
    if len(args) < 2:
        print("Usage: extract_ioctl.py <output_c_file> <target_ioctl_hex>")
        sys.exit(1)
    return args[0], args[1]

def find_dispatch_routine():
    """
    Very basic heuristic: finds DriverEntry, looks for assignments to
    DriverObject->MajorFunction[14] (IRP_MJ_DEVICE_CONTROL).
    For a production AVR, this needs to handle WDF and more complex WDM.
    Here we return the largest function as a fallback/example if not found immediately,
    or the user can pass an option. To keep it simple for the PoC, we decompile the Entry Point
    and any functions that have large switch statements.
    """
    # For this blueprint, we'll try to find any function processing the IOCTL
    # by looking for the constant in instructions.
    target_ioctl = int(args[1], 16) if args[1].startswith("0x") else int(args[1])
    
    fm = currentProgram.getFunctionManager()
    best_func = None
    
    # Simple heuristic: find the function that references the IOCTL constant
    # Or just return the most complex function (often the dispatcher)
    largest_func = None
    max_size = 0
    
    for f in fm.getFunctions(True):
        size = f.getBody().getNumAddresses()
        if size > max_size:
            max_size = size
            largest_func = f
            
    # For the sake of the blueprint, we return the largest function which is usually the dispatcher
    # In a full product, we would walk the DriverObject from DriverEntry.
    return largest_func

def main():
    global args
    args = getScriptArgs()
    if len(args) < 2:
        print("Error: missing arguments")
        return
        
    out_file = args[0]
    
    func = find_dispatch_routine()
    if not func:
        print("Could not find suitable dispatch routine.")
        return
        
    print("Decompiling: " + func.getName())
    
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    monitor = ConsoleTaskMonitor()
    results = decompiler.decompileFunction(func, 0, monitor)
    
    decompiled_c = results.getDecompiledFunction().getC()
    
    with open(out_file, 'w') as f:
        f.write(decompiled_c)
        
    print("Successfully wrote decompilation to " + out_file)
    
if __name__ == "__main__":
    main()
