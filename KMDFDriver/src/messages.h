#pragma once

#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)
#define IO_GET_CLIENT_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_ANY_ACCESS)

PDEVICE_OBJECT g_pDeviceObject = NULL;
UNICODE_STRING g_Dev, g_Dos;
