# Owned x86 test function: returns integer 42, reached once per 20 milliseconds.
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Capture41Synthetic {
 [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr n, uint t, uint p);
 [DllImport("kernel32.dll")] public static extern bool VirtualFree(IntPtr a, UIntPtr n, uint t);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int Function();
}
'@
$capturePointer = [Capture41Synthetic]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
if ($capturePointer -eq [IntPtr]::Zero) { throw 'allocation failed' }
try {
    [byte[]]$captureCode = 0xb8,0x2a,0,0,0,0xc3
    [Runtime.InteropServices.Marshal]::Copy($captureCode,0,$capturePointer,6)
    $captureFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($capturePointer,[Capture41Synthetic+Function])
    [Console]::WriteLine((@{pid=$PID;address=$capturePointer.ToInt64()} | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    for ($captureIndex=0; $captureIndex -lt 1500; $captureIndex++) {
        if ($captureFunction.Invoke() -ne 42) { throw 'function altered' }
        Start-Sleep -Milliseconds 20
    }
} finally {
    [void][Capture41Synthetic]::VirtualFree($capturePointer,[UIntPtr]::Zero,0x8000)
}

