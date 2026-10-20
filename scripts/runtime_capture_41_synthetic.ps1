# Owned x86 test function: returns integer 42, reached once per 20 milliseconds.
param([switch]$ApplicationBreakpoint)
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Capture41Synthetic {
 [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr n, uint t, uint p);
 [DllImport("kernel32.dll")] public static extern bool VirtualFree(IntPtr a, UIntPtr n, uint t);
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int Function();
 public delegate int Handler(IntPtr p);
 [DllImport("kernel32.dll")] public static extern IntPtr AddVectoredExceptionHandler(uint first, Handler handler);
 [DllImport("kernel32.dll")] public static extern uint RemoveVectoredExceptionHandler(IntPtr handler);
 public static IntPtr Counter;
 public static Handler Callback = new Handler(OnException);
 public static int OnException(IntPtr p) {
   if (Marshal.ReadInt32(Marshal.ReadIntPtr(p)) != unchecked((int)0x80000003)) return 0;
   Marshal.WriteInt32(Counter,Marshal.ReadInt32(Counter)+1);
   IntPtr context = Marshal.ReadIntPtr(p,4);
   Marshal.WriteInt32(context,184,Marshal.ReadInt32(context,184)+1);
   return -1;
 }
}
'@
$capturePointer = [Capture41Synthetic]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new(4096), 0x3000, 0x40)
if ($capturePointer -eq [IntPtr]::Zero) { throw 'allocation failed' }
try {
    [byte[]]$captureCode = 0xb8,0x2a,0,0,0,0xc3
    $captureHandlerHandle = [IntPtr]::Zero
    if ($ApplicationBreakpoint) {
        [Capture41Synthetic]::Counter = [IntPtr]::Add($capturePointer,128)
        $captureHandlerHandle = [Capture41Synthetic]::AddVectoredExceptionHandler(1,[Capture41Synthetic]::Callback)
        $captureCode = [byte[]](0xcc,0xb8,0x2a,0,0,0,0xc3)
    }
    [Runtime.InteropServices.Marshal]::Copy($captureCode,0,$capturePointer,$captureCode.Length)
    $captureFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($capturePointer,[Capture41Synthetic+Function])
    [Console]::WriteLine((@{pid=$PID;address=$capturePointer.ToInt64();counter=[Capture41Synthetic]::Counter.ToInt64()} | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 500
    for ($captureIndex=0; $captureIndex -lt 1500; $captureIndex++) {
        if ($captureFunction.Invoke() -ne 42) { throw 'function altered' }
        Start-Sleep -Milliseconds 20
    }
} finally {
    if ($captureHandlerHandle -ne [IntPtr]::Zero) { [void][Capture41Synthetic]::RemoveVectoredExceptionHandler($captureHandlerHandle) }
    [void][Capture41Synthetic]::VirtualFree($capturePointer,[UIntPtr]::Zero,0x8000)
}
