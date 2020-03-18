#include "Driver.h"
#define PROCESS_TERMINATE         0x0001    
#define PROCESS_VM_OPERATION      0x0008    
#define PROCESS_VM_READ           0x0010    
#define PROCESS_VM_WRITE          0x0020  
PVOID g_pRegiHandle = NULL;
ULONG PID=NULL;
NTSTATUS OB();
char* GetProcessImageNameByProcessID(ULONG ulProcessID);
ULONG64 GetProcessModuleBase(IN ULONG ProcessId, IN UNICODE_STRING ModuleName)
{
	ULONG64 ModulesBase = 0;
	NTSTATUS nStatus;
	KAPC_STATE KAPC = { 0 };
	PEPROCESS  pEProcess = NULL; //EPROCESS结构指针;

	PPEB64 pPEB64 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = NULL; //LDR链表入口;
	PLIST_ENTRY64 pListEntryStart64 = NULL, pListEntryEnd64 = NULL;; //链表头节点、尾节点;

	PPEB32 pPEB32 = NULL; //PEB结构指针;
	PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = NULL; //LDR链表入口;
	PLIST_ENTRY32 pListEntryStart32 = NULL, pListEntryEnd32 = NULL; //链表头节点、尾节点;

	//获取进程的EPROCESS结构指针;
	nStatus = PsLookupProcessByProcessId((HANDLE)ProcessId, &pEProcess);
	if (!NT_SUCCESS(nStatus) && !MmIsAddressValid(pEProcess))
	{
		return 0;
	}
	KeStackAttachProcess(pEProcess, &KAPC);

	pPEB64 = PsGetProcessPeb(pEProcess);
	pListEntryStart64 = pListEntryEnd64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)pPEB64->Ldr)->InMemoryOrderModuleList.Flink);
	do {
		pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(pListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
		//输出DLL基质 长度 名字;
		//DbgPrint("[Orange64] Base:%p Size:%ld Name:%wZ\n", (PVOID)pLdrDataEntry64->DllBase, (ULONG)pLdrDataEntry64->SizeOfImage, &pLdrDataEntry64->BaseDllName);

		UNICODE_STRING QueryModuleName = { 0 };
		RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry64->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
		{
			ModulesBase = (ULONG64)pLdrDataEntry64->DllBase;
			goto exit;
		}
		pListEntryStart64 = (PLIST_ENTRY64)pListEntryStart64->Flink;

	} while (pListEntryStart64 != pListEntryEnd64);

#ifdef _AMD64_	//或wow64进程;	PsIs64BitProcess

	//获取PEB指针
	pPEB32 = PsGetProcessWow64Process(pEProcess);
	pListEntryStart32 = pListEntryEnd32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)pPEB32->Ldr)->InMemoryOrderModuleList.Flink);
	do {
		pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(pListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
		//输出DLL基质 长度 名字;
		//DbgPrint("[Orange64] Base:%p Size:%ld Name:%wZ\n", (PVOID)pLdrDataEntry32->DllBase, (ULONG)pLdrDataEntry32->SizeOfImage, &pLdrDataEntry32->BaseDllName);
		UNICODE_STRING QueryModuleName = { 0 };
		RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry32->BaseDllName.Buffer);
		if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
		{
			ModulesBase = (ULONG64)pLdrDataEntry32->DllBase;
			goto exit;
		}
		pListEntryStart32 = (PLIST_ENTRY32)pListEntryStart32->Flink;

	} while (pListEntryStart32 != pListEntryEnd32);

#endif
exit:
	KeUnstackDetachProcess(&KAPC);
	ObDereferenceObject(pEProcess);
	return ModulesBase;
}
ULONG GetModuleBaseWow64(_In_ HANDLE ProcessID, IN UNICODE_STRING usModuleName)
{

	ULONGLONG BaseAddr = 0;
	KAPC_STATE KAPC = { 0 };
	PEPROCESS ep;
	NTSTATUS status;
	status = PsLookupProcessByProcessId(ProcessID, &ep);
	KeStackAttachProcess(ep, &KAPC);
	PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(ep);
	if (pPeb == NULL || pPeb->Ldr == 0)
	{
		KeUnstackDetachProcess(&KAPC);
		return 0;
	}

	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
		pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY32 LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

		if (LdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}
		// Current Module Name in ListFlink
		UNICODE_STRING usCurrentName = { 0 };
		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
		BaseAddr = (ULONG)LdrEntry->DllBase;
		KdPrint(("%d\n", BaseAddr));
		// cmp module name
		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
		{
			BaseAddr = (ULONGLONG)LdrEntry->DllBase;
			KdPrint(("%d\n", BaseAddr));
			KeUnstackDetachProcess(&KAPC);
			return BaseAddr;
		}
	}

	KeUnstackDetachProcess(&KAPC);
	return 0;
}
NTSTATUS AllocMemory(IN ULONG ProcessPid, IN SIZE_T Length, OUT PVOID Buffer)
{
	NTSTATUS	Status = STATUS_SUCCESS;
	PEPROCESS	pEProcess = NULL;
	KAPC_STATE	ApcState = { 0 };
	PVOID BaseAddress = NULL;
	PEPROCESS ep;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessPid, &pEProcess);
	if (!NT_SUCCESS(Status) && !MmIsAddressValid(pEProcess)) { return STATUS_UNSUCCESSFUL; }
	__try
	{
		KeStackAttachProcess(pEProcess, &ApcState);
		Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		RtlZeroMemory(BaseAddress, Length);
		*(PVOID *)Buffer = BaseAddress;
		KeUnstackDetachProcess(&ApcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&ApcState);
		Status = STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(pEProcess);
	return Status;
}
VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, DEVICE_LINK_NAME);
	IoDeleteSymbolicLink(&symLinkName);
if (PID!=NULL)
{
	ObUnRegisterCallbacks(g_pRegiHandle);
}
	KdPrint(("驱动卸载\n"));
	IoDeleteDevice(pDriverObj->DeviceObject);
}
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
BOOLEAN MDLWriteMemory(ULONG ProcessID, ULONG pBaseAddress, PVOID pWriteData, ULONG writeDataSize)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	KAPC_STATE apcstate;
	NTSTATUS status;
	PEPROCESS EP;
	status = PsLookupProcessByProcessId(ProcessID, &EP);
	KeStackAttachProcess(EP, &apcstate);
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	_try{
		ProbeForWrite(pBaseAddress, writeDataSize, sizeof(ULONG));
		RtlCopyMemory(pNewAddress, pWriteData, writeDataSize);
	}
	except(1)
	{
		MmUnmapLockedPages(pNewAddress, pMdl);
		IoFreeMdl(pMdl);
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	KeUnstackDetachProcess(&apcstate);
	ObDereferenceObject(EP);
	return TRUE;
}
BOOLEAN MDLreadMemory(ULONG ProcessID, ULONG pBaseAddress, ULONG writeDataSize, PVOID Buffer)
{
	PMDL pMdl = NULL;
	PVOID pNewAddress = NULL;
	KAPC_STATE apcstate;
	NTSTATUS status;
	PEPROCESS EP;
	status = PsLookupProcessByProcessId(ProcessID, &EP);
	KeStackAttachProcess(EP, &apcstate);
	pMdl = MmCreateMdl(NULL, pBaseAddress, writeDataSize);
	if (NULL == pMdl)
	{
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	pNewAddress = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pNewAddress)
	{
		IoFreeMdl(pMdl);
	}
	_try{
		ProbeForRead(pBaseAddress, writeDataSize, sizeof(ULONG));
		RtlCopyMemory(Buffer, pNewAddress, writeDataSize);
	}
	except(1)
	{
		MmUnmapLockedPages(pNewAddress, pMdl);
		IoFreeMdl(pMdl);
		KeUnstackDetachProcess(&apcstate);
		ObDereferenceObject(EP);
		return FALSE;
	}

	MmUnmapLockedPages(pNewAddress, pMdl);
	IoFreeMdl(pMdl);
	KeUnstackDetachProcess(&apcstate);
	ObDereferenceObject(EP);
	return TRUE;
}
VOID CHAR_TO_UNICODE_STRING(PCHAR ch, PUNICODE_STRING unicodeBuffer)
{
	ANSI_STRING ansiBuffer;
	UNICODE_STRING buffer_proc;
	ULONG len = strlen(ch);
	ansiBuffer.Buffer = ch;
	ansiBuffer.Length = ansiBuffer.MaximumLength = (USHORT)len;
	RtlAnsiStringToUnicodeString(unicodeBuffer, &ansiBuffer, TRUE);
}
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	NTSTATUS Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION  IoStackLocation = NULL;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG InputDataLength = 0, OutputDataLength = 0, IoControlCode = 0;

	IoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
	IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	InputDataLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	OutputDataLength = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

	switch (IoControlCode)
	{
	case IOCTL_IO_ReadMemory:
	{
								
								MDLreadMemory(((PDataStruct)InputData)->ProcessPid, ((PDataStruct)InputData)->TargetAddress, ((PDataStruct)InputData)->Length,OutputData);
								Status = STATUS_SUCCESS;
								break;
	}
	case IOCTL_IO_WriteMemory:
	{
	
								PVOID g_writeBuf = ExAllocatePoolWithTag(NonPagedPool, ((PDataStruct)InputData)->Length, '1234');					
								RtlCopyMemory(g_writeBuf, (((PDataStruct)InputData)->Buffer), ((PDataStruct)InputData)->Length);
								MDLWriteMemory(((PDataStruct)InputData)->ProcessPid, ((PDataStruct)InputData)->TargetAddress, g_writeBuf, ((PDataStruct)InputData)->Length);
								ExFreePool(g_writeBuf);
								 Status = STATUS_SUCCESS;
								 break;
	}
	case IOCTL_IO_AllocMemory:
	{
								 AllocMemory(((PDataStruct)InputData)->ProcessPid, ((PDataStruct)InputData)->Length, OutputData);
								 Status = STATUS_SUCCESS;
								 break;
	}
	case IOCTL_IO_GetProcessModules:
	{
									   ANSI_STRING AnsiBuffer = {0};
									   UNICODE_STRING  ModuleName = { 0 };
									   RtlInitAnsiString(&AnsiBuffer, ((PDataStruct)InputData)->Buffer);
									   RtlAnsiStringToUnicodeString(&ModuleName, &AnsiBuffer, TRUE);
									   ULONG BaseAddress = GetModuleBaseWow64(((PDataStruct)InputData)->ProcessPid, ModuleName);
									   RtlCopyMemory(OutputData, &BaseAddress, sizeof(BaseAddress));									 
									   Status = STATUS_SUCCESS;
									   break;
	}
	case IOCTL_IO_Protect:
	{
							 PID = ((PDataStruct)InputData)->ProcessPid;
							 OB();
								 Status = STATUS_SUCCESS;
								 break;
	}
	default:
		Status = STATUS_UNSUCCESSFUL;
		break;
	}
	if (Status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = OutputDataLength;
	else
		pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}
OB_PREOP_CALLBACK_STATUS precessCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (pid=(HANDLE)PID)//要保护的进程名字
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)//进程终止
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)//openprocess
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)//内存读
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)//内存写
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}
NTSTATUS OB()
{
	OB_OPERATION_REGISTRATION oor;
	OB_CALLBACK_REGISTRATION ob;
	//注册回调函数
	oor.ObjectType = PsProcessType;
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	oor.PreOperation = precessCallBack;
	oor.PostOperation = NULL;
	ob.Version = OB_FLT_REGISTRATION_VERSION;
	ob.OperationRegistrationCount = 1;
	ob.OperationRegistration = &oor;
	RtlInitUnicodeString(&ob.Altitude, L"321000");
	ob.RegistrationContext = NULL;
	return ObRegisterCallbacks(&ob, &g_pRegiHandle);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	KdPrint(("Load\n"));
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	UNREFERENCED_PARAMETER(pRegistryString);
	PDEVICE_OBJECT pDevObj;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	Status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(Status)) return Status;
	RtlInitUnicodeString(&ustrLinkName, DEVICE_LINK_NAME);
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(pDevObj);
		return Status;
	}
	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
	return STATUS_SUCCESS;
}