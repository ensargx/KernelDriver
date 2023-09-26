#pragma once

#include <Windows.h>

#define IO_GET_CLIENT_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_GET_MY_CLASS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x668, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x669, METHOD_BUFFERED, FILE_ANY_ACCESS)


class KernelInterface
{
public:
    HANDLE hDriver;
    KernelInterface(LPCSTR registryPath);
    ~KernelInterface();

    ULONG GetClientAddress();
};

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