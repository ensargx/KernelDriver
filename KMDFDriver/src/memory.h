#pragma once

#include "messages.h"
#include "ntapi.h"
#include <ntddk.h>

struct MemoryReadRequest
{
    INT PID;
    SIZE_T Size;
    PVOID pInAddress;
    PVOID pOutBuffer;
};

struct MemoryWriteRequest
{
    INT PID;
    SIZE_T size;
    PVOID address;
    PVOID inBuffer;
};

extern "C" namespace Memory
{
    NTSTATUS Read(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size);
    NTSTATUS Write(PEPROCESS Process, PVOID TargetAddress, PVOID SourceAddress, SIZE_T Size);
}
