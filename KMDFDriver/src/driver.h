#pragma once

#include <ntifs.h>

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);

extern "C" NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject);

NTSTATUS CreateCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS CloseCall(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);

NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);