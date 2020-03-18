#pragma once
#include <ntddk.h>
#include "Header.h"


#define DEVICE_NAME				L"\\Device\\ilink"
#define DEVICE_LINK_NAME	L"\\DosDevices\\ilink"

#define IOCTL_IO_ReadMemory		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_WriteMemory		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_AllocMemory		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_GetProcessModules		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_IO_Protect	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)


//定义结构
typedef struct _DataStruct {
	ULONG	ProcessPid;
	ULONG	TargetAddress;
	ULONG	Length;
	ULONG   Buffer;
} DataStruct, *PDataStruct;
