# Checker-owned x86 wrapper -> callee -> nested helper. These are synthetic bytes.
param([ValidateSet('Normal','WrongCaller','WrongStack','NestedMismatch','Timeout','Exception')][string]$Mode='Normal')
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Paired41Synthetic {
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
$pairedPointer = [Paired41Synthetic]::VirtualAlloc([IntPtr]::Zero,[UIntPtr]::new(4096),0x3000,0x40)
if ($pairedPointer -eq [IntPtr]::Zero) { throw 'allocation failed' }
$pairedHandler = [IntPtr]::Zero
try {
    # push 7; call +64; ret. Callee: call +96; mov eax,42; ret 4.
    [byte[]]$pairedWrapper = 0x6a,7,0xe8,0x39,0,0,0,0xc3
    [byte[]]$pairedCallee = 0xe8,0x1b,0,0,0,0xb8,42,0,0,0,0xc2,4,0
    [byte[]]$pairedNested = 0x31,0xc0,0xc3
    if ($Mode -eq 'WrongStack') {
        # Jump to wrapper return with ESP=entryESP-4; return stub repairs the
        # synthetic stack after debugger detaches, so the child remains healthy.
        $pairedWrapper = [byte[]](0x6a,7,0xe8,0x39,0,0,0,0x83,0xc4,12,0xc3)
        $pairedCallee = [byte[]](0xb8,42,0,0,0,0x50,0xe9,0xbc,0xff,0xff,0xff)
    }
    if ($Mode -eq 'Timeout') { $pairedCallee = [byte[]](0x90,0xf3,0x90,0xeb,0xfc) }
    if ($Mode -eq 'NestedMismatch') {
        # Recursively invoke this same wrapper once. The inner RET4 reaches the
        # identical return address on the selected thread, but a different ESP.
        $pairedCounter = [IntPtr]::Add($pairedPointer,256)
        [Runtime.InteropServices.Marshal]::WriteInt32($pairedCounter,1)
        [byte[]]$pairedCounterBytes = [BitConverter]::GetBytes($pairedCounter.ToInt32())
        $pairedCallee = [byte[]](@(0xa1) + $pairedCounterBytes + @(0x85,0xc0,0x74,11,0xff,0x0d) +
            $pairedCounterBytes + @(0xe8,0xac,0xff,0xff,0xff,0xb8,42,0,0,0,0xc2,4,0))
    }
    if ($Mode -eq 'Exception') {
        [Paired41Synthetic]::Counter = [IntPtr]::Add($pairedPointer,256)
        $pairedHandler = [Paired41Synthetic]::AddVectoredExceptionHandler(1,[Paired41Synthetic]::Callback)
        if ($pairedHandler -eq [IntPtr]::Zero) { throw 'handler failed' }
        $pairedNested = [byte[]](0xcc,0x31,0xc0,0xc3)
    }
    [Runtime.InteropServices.Marshal]::Copy($pairedWrapper,0,$pairedPointer,$pairedWrapper.Length)
    [Runtime.InteropServices.Marshal]::Copy($pairedCallee,0,[IntPtr]::Add($pairedPointer,64),$pairedCallee.Length)
    [Runtime.InteropServices.Marshal]::Copy($pairedNested,0,[IntPtr]::Add($pairedPointer,96),$pairedNested.Length)
    $pairedFunction = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($pairedPointer,[Paired41Synthetic+Function])
    $pairedReturnOffset = if ($Mode -eq 'WrongCaller') { 8 } else { 7 }
    [Console]::WriteLine((@{pid=$PID;entry=$pairedPointer.ToInt64()+64;returnAddress=$pairedPointer.ToInt64()+$pairedReturnOffset;counter=$pairedPointer.ToInt64()+256} | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 500
    for ($pairedIndex=0; $pairedIndex -lt 1500; $pairedIndex++) {
        if ($pairedFunction.Invoke() -ne 42) { throw 'function altered' }
        Start-Sleep -Milliseconds 20
    }
} finally {
    if ($pairedHandler -ne [IntPtr]::Zero) { [void][Paired41Synthetic]::RemoveVectoredExceptionHandler($pairedHandler) }
    [void][Paired41Synthetic]::VirtualFree($pairedPointer,[UIntPtr]::Zero,0x8000)
}
