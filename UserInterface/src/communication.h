#pragma once

#include <Windows.h>

#define IO_GET_CLIENT_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)

class KernelInterface
{
public:
    HANDLE hDriver;
    KernelInterface(LPCSTR registryPath);
    ~KernelInterface();

    ULONG GetClientAddress();
};