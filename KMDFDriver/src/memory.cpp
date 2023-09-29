#include "memory.h"

NTSTATUS Memory::Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	if (!Process)
		return STATUS_INVALID_PARAMETER;

	size_t bytes = 0;
	NTSTATUS status = MmCopyVirtualMemory(Process, SourceAddress, IoGetCurrentProcess(), TargetAddress, Size, KernelMode, &bytes);
	if (!NT_SUCCESS(status) || !bytes)
	{
		return STATUS_INVALID_ADDRESS;
	}
	return status;
}

NTSTATUS Memory::Write(PEPROCESS Process, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size)
{
	if (!Process)
        return STATUS_INVALID_PARAMETER;

	size_t bytes = 0;
	NTSTATUS status = MmCopyVirtualMemory(IoGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &bytes);
	if (!NT_SUCCESS(status) || !bytes)
	{
        return STATUS_INVALID_ADDRESS;
    }

	return STATUS_SUCCESS;
}
