#pragma once

#define DEBUG_PREFIX "KMDFDriver: "
#define DebugMessage(x, ...) DbgPrintEx(0, 0, DEBUG_PREFIX x, __VA_ARGS__)

#define IO_GET_CLIENT_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)
// TEST AMA�LI EKLEND�
#define IO_GET_MY_CLASS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x667, METHOD_BUFFERED, FILE_ANY_ACCESS)
class PCommonClass
{
public:
    int v1 = 0;
    int v2 = 2;
};
// END TEST
