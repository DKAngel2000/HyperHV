HyperHvDllPatcher.exe
=====================

Double-click the EXE to open the GUI. It describes the Intel Hyper-V service
error 0xC035001E and the EPT allocation change, then lets you browse to the
hyperhv.dll used by the affected application. The tool stages and verifies the
patch, renames the original to hyperhv.dll.bak, then installs the patched file
as hyperhv.dll. It will not overwrite an existing backup. If the DLL is already
patched, it says so and does not change any files.

Command-line use:

  HyperHvDllPatcher.exe hyperhv.dll

The EXE first checks the ten reviewed code-layout profiles. For a new layout,
the file picker asks whether to try the experimental built-in PE/x64 scanner.
From a command prompt, opt in with:

  HyperHvDllPatcher.exe --experimental hyperhv.dll

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
