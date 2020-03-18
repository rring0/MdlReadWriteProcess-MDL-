#pragma once
#ifndef Memory_H
#define Memory_H
#include <ntddk.h>
//#include <windef.h>

//定义数据结构
typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG/*PPEB_LDR_DATA32*/ Ldr;
} PEB32, *PPEB32;

typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	UCHAR Padding0[4];
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64/*PPEB_LDR_DATA64*/ Ldr;
} PEB64, *PPEB64;


typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	ULONG ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;


typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;


typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];     /*线程的apc链表 只有两个 内核态和用户态*/
	struct _KPROCESS *Process;               /*当前线程的进程体   PsGetCurrentProcess()*/
	BOOLEAN KernelApcInProgress;             /*内核APC正在执行*/
	BOOLEAN KernelApcPending;                /*内核APC正在等待执行*/
	BOOLEAN UserApcPending;                  /*用户APC正在等待执行*/
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;


//定义全局API

NTKERNELAPI	NTSTATUS	PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS *Process);
NTKERNELAPI	VOID		KeStackAttachProcess(_Inout_ PEPROCESS PROCESS, _Out_ PRKAPC_STATE ApcState);
NTKERNELAPI	VOID		KeUnstackDetachProcess(_In_ PRKAPC_STATE ApcState);
NTKERNELAPI PPEB64		PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PPEB32		PsGetProcessWow64Process(_In_ PEPROCESS  Process);


typedef struct _MEMORY_BASIC_INFORMATION
{
	PVOID  BaseAddress;
	PVOID  AllocationBase;
	ULONG  AllocationProtect;
	SIZE_T RegionSize;
	ULONG  State;
	ULONG  Protect;
	ULONG  Type;

} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;


//MEMORY_INFORMATION_CLASS定义  
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,          //内存基本信息  
	MemoryWorkingSetInformation,       //工作集信息  
	MemoryMappedFilenameInformation    //内存映射文件名信息  

} MEMORY_INFORMATION_CLASS;

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
_In_		HANDLE		ProcessHandle,
_Inout_		PVOID		*BaseAddress,
_In_		ULONG_PTR	ZeroBits,
_Inout_		PSIZE_T		RegionSize,
_In_		ULONG		AllocationType,
_In_		ULONG		Protect
);


#endif
