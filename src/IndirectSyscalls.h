#pragma once
#include <windows.h>
#include <winternl.h>
#include "Utils.h"

typedef struct _PEB_LDR_DATA_CUSTOM
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA_CUSTOM, *PPEB_LDR_DATA_CUSTOM;

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_CUSTOM, * PLDR_DATA_TABLE_ENTRY_CUSTOM;

typedef struct _SYSCALL_ENTRY {
    DWORD       SSN;
    ULONG_PTR   Gadget;
} SYSCALL_ENTRY;

typedef struct _SYSCALL_TABLE {
    SYSCALL_ENTRY NtQueryInformationProcess;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

typedef struct _SYSCALL_CONTEXT {
    DWORD     Ssn;
    ULONG_PTR GadgetAddress;

    ULONG_PTR rcx;
    ULONG_PTR rdx;
    ULONG_PTR r8;
    ULONG_PTR r9;
    ULONG_PTR Arg5;
    ULONG_PTR Arg6;
} SYSCALL_CONTEXT, *PSYSCALL_CONTEXT;

HMODULE GetModuleByHash(DWORD dwTargetHash);
BOOL initIndirectSyscalls();

NTSTATUS SysNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);