#include "manuelmap.h"
#include "messages.h"

NTSTATUS ManualMapDll(PEPROCESS Process, PUNICODE_STRING DllPath)
{
    NTSTATUS status = STATUS_SUCCESS;

    // 1, 2 - Load DLL into memory
    PVOID DllBase = NULL;
    status = LoadDllIntoMemory(Process, DllPath, &DllBase);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to load DLL into memory (LoadDllIntoMemory) Error: 0x%08X\n", status);
        return status;
    }

    // 3 - Resolve DLL imports
    status = ResolveDllImports(Process, DllBase);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to resolve DLL imports (ResolveDllImports) Error: 0x%08X\n", status);
        return status;
    }

    // 4 - Execute DLL entry point
    HANDLE DllThreadHandle = NULL;
    status = ExecuteDllEntry(Process, DllBase, &DllThreadHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "Failed to execute DLL entry point (ExecuteDllEntry) Error: 0x%08X\n", status);
        return status;
    }

    // 5 - Free DLL from memory
    status = FreeDllFromMemory(Process, DllBase);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "Failed to free DLL from memory (FreeDllFromMemory) Error: 0x%08X\n", status);
        return status;
    }

    DebugMessage("Successfully mapped DLL into process\n");

    return status;
}

NTSTATUS LoadDllIntoMemory(PEPROCESS Process, PUNICODE_STRING DllPath, PVOID* DllBase)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(DllPath);
    UNREFERENCED_PARAMETER(DllBase);


    NTSTATUS status = STATUS_SUCCESS;

    return status;
}

NTSTATUS RelocateDll(PEPROCESS Process, PVOID NewBase)
{
    UNREFERENCED_PARAMETER(Process);
    NTSTATUS status = STATUS_SUCCESS;

    // Get DLL header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)NewBase;

    // Check if DLL is valid
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DebugMessage("Invalid DLL\n");
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    // Get NT header
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)NewBase + dosHeader->e_lfanew);

    // Check if DLL is valid
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DebugMessage("Invalid DLL\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get DLL image base
    PVOID oldBase = (PVOID)ntHeaders->OptionalHeader.ImageBase;

    // Get DLL image size
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // Allocate memory for DLL
    PVOID newBase = NULL;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &newBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Copy DLL into new memory
    RtlCopyMemory(newBase, oldBase, imageSize);

    return status;
}

NTSTATUS ResolveDllImports(PEPROCESS Process, PVOID DllBase)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(DllBase);
    // TODO: Implement
    return STATUS_SUCCESS;
}

NTSTATUS ExecuteDllEntry(PEPROCESS Process, PVOID DllBase, HANDLE* DllThreadHandle)
{
    UNREFERENCED_PARAMETER(Process);

    NTSTATUS status = STATUS_SUCCESS;

    // Get DLL header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBase;
    
    // Check if DLL is valid
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DebugMessage("Invalid DLL\n");
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }

    // Get NT header
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)DllBase + dosHeader->e_lfanew);

    // Check if DLL is valid
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DebugMessage("Invalid DLL\n");
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Get DLL entry point
    PVOID dllEntryPoint = (PVOID)((PUCHAR)DllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    // Create thread to execute DLL entry point
    HANDLE DllEntryPointThreadHandle = NULL;

    // Execute DLL entry point
    status = PsCreateSystemThread(&DllEntryPointThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)dllEntryPoint, NULL);
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to execute DLL entry point\n");
        return status;
    }

    *DllThreadHandle = DllEntryPointThreadHandle;

    return status;
}

NTSTATUS FreeDllFromMemory(PEPROCESS Process, PVOID DllBase)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(DllBase);
    // TODO: Implement
    return STATUS_SUCCESS;
}
