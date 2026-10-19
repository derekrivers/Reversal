# Harmless x86 test target: owned 64-byte allocation and a blocked input read.
$ErrorActionPreference = 'Stop'
$testPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal(64)
try {
    $testBytes = [byte[]](0..63)
    [Runtime.InteropServices.Marshal]::Copy($testBytes, 0, $testPointer, 64)
    [Console]::WriteLine((@{ pid = $PID; address = $testPointer.ToInt64(); size = 64 } | ConvertTo-Json -Compress))
    [Console]::Out.Flush()
    [void][Console]::ReadLine()
} finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($testPointer)
}
