#include "communication.h"

KernelInterface::KernelInterface(LPCSTR registeryName)
{
    hDriver = CreateFileA(registeryName, GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
}

KernelInterface::~KernelInterface()
{
    CloseHandle(hDriver);
}

ULONG KernelInterface::GetClientAddress()
{
    ULONG Address = 0;
    DWORD BytesReturned = 0;

    DeviceIoControl(hDriver, IO_GET_CLIENT_ADDRESS, &Address, sizeof(Address), &Address, sizeof(Address), &BytesReturned, NULL);
    return Address;
}

