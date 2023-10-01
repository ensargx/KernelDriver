#include "communication.h"
#include <iostream>

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")


struct ManuelMapRequest
{
    INT PID;
    UNICODE_STRING DllPath;
};

void loopThread()
{
    while (true)
    {
        std::cout << "Looping\n";
        Sleep(5000);
    }
}

int main()
{
    std::cout << "Hello World!\n";
    HANDLE hDriver = CreateFileA("\\\\.\\MyDriver", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (hDriver == INVALID_HANDLE_VALUE)
    {
        std::cout << "Failed to get a handle to the driver\n";
        return 1;
    }
    std::cout << "Got a handle to the driver\nPress Enter to continue...\n";
    std::cin.get();

    int PID;

    UNICODE_STRING DllPath;
    // Initialize the UNICODE_STRING with a wide character string
    // WCHAR myString[] = L"C:\\Users\\admin\\Desktop\\basicdll.dll";

    // Initialize the UNICODE_STRING structure
    // RtlInitUnicodeString(&DllPath, myString);

    ManuelMapRequest request;
    // request.PID = PID;
    // request.DllPath = DllPath;

    HANDLE hThread;
    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)loopThread, NULL, NULL, NULL);
    if (!hThread)
    {
        std::cout << "Failed to create thread\n";
        return 1;
    }
    std::cout << "Thread created, handle: " << std::hex << hThread << "\n";
    std::cout << "Press enter to continue\n";

    request.PID = GetThreadId(hThread);
    std::cin.get();

    std::cout << "Sending IOCTL to the driver\n";
    DWORD bytesIO;
    BOOL result = DeviceIoControl(hDriver, IO_MANUEL_MAP_DLL, &request, sizeof(ManuelMapRequest), NULL, 0, &bytesIO, NULL);
    if (!result)
    {
        std::cout << "Failed to send IOCTL to the driver\n";
        return 1;
    }

    return 0;
}