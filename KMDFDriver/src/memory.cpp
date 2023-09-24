#include "memory.h"

NTSTATUS Memory::Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	if (!Process)
		STATUS_INVALID_PARAMETER;

	size_t bytes = 0;
	NTSTATUS status = MmCopyVirtualMemory(Process, SourceAddress, IoGetCurrentProcess(), TargetAddress, Size, KernelMode, &bytes);
	if (!NT_SUCCESS(status) || !bytes)
	{
		return STATUS_INVALID_ADDRESS;
	}
	return status;
}
