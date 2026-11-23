HyperHvDllPatcher.exe
=====================

Double-click the EXE to open the GUI. It describes the Intel Hyper-V service
error 0xC035001E and the EPT allocation change, then lets you browse to the
hyperhv.dll used by the affected application. The tool stages and verifies the
patch, renames the original to hyperhv.dll.bak, then installs the patched file
as hyperhv.dll. It will not overwrite an existing backup. If the DLL is already
patched, it reports that and makes no changes unless test signing was selected.
For an already-patched DLL, test signing saves the unsigned patched copy as
`hyperhv.dll.unsigned.bak` before installing the signed version.

Command-line use:

  HyperHvDllPatcher.exe hyperhv.dll

The EXE first checks the ten reviewed code-layout profiles. For a new layout,
the file picker asks whether to try the experimental built-in PE/x64 scanner.
From a command prompt, opt in with:

  HyperHvDllPatcher.exe --experimental hyperhv.dll

Optional test signing: select "Test-sign for other PCs" in the GUI, or add
`--test-sign` on the command line. Signing is built into the
EXE through Windows cryptography APIs; Visual Studio, the WDK, and SignTool are
not required. The patcher creates a temporary self-signed test certificate,
embeds a SHA-256 Authenticode signature, exports the public certificate as a
`HyperHV-TestCert-<fingerprint>.cer` beside the DLL, then deletes the temporary
private signing key. This is for local testing, not production signing. Because
the key is temporary, signing another DLL creates a new certificate and a new
`.cer` file.

To test the same signed DLL on another PC, copy both `hyperhv.dll` and its
matching `.cer` file to that PC. For Windows kernel-mode test signing, import
the `.cer` into the test PC's Local Machine Trusted Root Certification
Authorities store (and Trusted Publishers if the installation flow requires
it), enable test-signing from an elevated command prompt with
`bcdedit /set testsigning on`, then restart Windows. The patcher does not change
boot settings or certificate trust stores. Test mode may be blocked by Secure
Boot policy; Microsoft documents the test-signing requirements and setup at
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option
and
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates.

The scanner identifies imports, helper routines, the EPT table field at offset
0x228, the allocator call, and exactly two matching free calls. It proceeds only
when every required match is unique. Partial or ambiguous matches are refused.
Experimental patching is heuristic and should be reviewed before use; no static
pattern scanner can guarantee compatibility with every future build. It uses
the same backup and replacement steps as the reviewed profiles.

The EXE does not require PowerShell, Ghidra, internet access, or a separate
runtime installation. It is built with the C++ runtime linked in. The C++ source
is included beside it for inspection and future maintenance.

Reference diff: ept-identity-table-noncontiguous.diff is included in the
repository. It changes EPT table allocation from
PlatformMemAllocateContiguousZeroedMemory to PlatformMemAllocateZeroedNonPagedPool,
and the two matching cleanup calls from MmFreeContiguousMemory to
PlatformMemFreePool. The binary patcher applies the corresponding compiled
changes only to those EPT table paths; other contiguous-memory allocations,
including VMXON and VMCS regions, are left alone. The diff is for reference; the
EXE does not read it at runtime. The tool does not load the DLL. Digital
signatures are not checked or preserved; changing code may invalidate one.

Exit codes: 0 success/already patched, 2 input error, 3 unsupported layout,
4 experimental scan refused, 5 output error.
