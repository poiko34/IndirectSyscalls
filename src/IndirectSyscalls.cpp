#include "IndirectSyscalls.h"
#include <iostream>
#include <iomanip>

HMODULE g_Ntdll;
SYSCALL_TABLE g_Sys;

extern "C" NTSTATUS UniversalSyscall(PSYSCALL_CONTEXT);

HMODULE GetModuleByHash(DWORD dwTargetHash) {
#if defined(_WIN64)
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    PPEB_LDR_DATA_CUSTOM pLdr = (PPEB_LDR_DATA_CUSTOM)pPeb->Ldr;
    
    LIST_ENTRY* pListHead = &pLdr->InLoadOrderModuleList;
    LIST_ENTRY* pListEntry = pListHead->Flink;

    while (pListEntry != pListHead) {
        LDR_DATA_TABLE_ENTRY_CUSTOM* pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);

        if (pEntry->BaseDllName.Buffer != NULL) {
            if (runtime_fnv1a_w(pEntry->BaseDllName.Buffer) == dwTargetHash) {
                std::cout << "[+] Found module via PEB hash: " << std::hex << (void*)pEntry->DllBase << std::dec << "\n";
                return (HMODULE)pEntry->DllBase;
            }
        }
        pListEntry = pListEntry->Flink;
    }
    return NULL;
}

FARPROC GetProcAddressByHash(HMODULE hModule, DWORD dwTargetHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((PBYTE)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return NULL;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + exportDirRVA);

    DWORD* pNames = (DWORD*)((PBYTE)hModule + pExportDir->AddressOfNames);
    DWORD* pFunctions = (DWORD*)((PBYTE)hModule + pExportDir->AddressOfFunctions);
    WORD* pOrdinals = (WORD*)((PBYTE)hModule + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szFunctionName = (char*)((PBYTE)hModule + pNames[i]);
        if (runtime_fnv1a(szFunctionName) == dwTargetHash) {
            WORD wOrdinal = pOrdinals[i];
            DWORD dwFuncRVA = pFunctions[wOrdinal];
            FARPROC pFunc = (FARPROC)((PBYTE)hModule + dwFuncRVA);
            std::cout << "[+] Resolved function '" << szFunctionName << "' -> " << (void*)pFunc << "\n";
            return pFunc;
        }
    }
    return NULL;
}

DWORD64 FindSyscallAddressInFunction(PBYTE funcAddress) {
    for (int i = 0; i <= 30; i++) {
        if (funcAddress[i] == 0x0F && funcAddress[i + 1] == 0x05 && funcAddress[i + 2] == 0xC3) {
            DWORD64 gadget = (DWORD64)(funcAddress + i);
            std::cout << "[+] Found 'syscall; ret' gadget at: " << (void*)gadget << "\n";
            return gadget;
        }
    }
    std::cout << "[-] Warning: 'syscall; ret' gadget NOT found in target stub range!\n";
    return 0;
}

SYSCALL_ENTRY GetSyscallData(DWORD syscallHash, HMODULE hNtdll) {
    SYSCALL_ENTRY entry = { 0, 0 };

    std::cout << "[*] Resolving syscall for hash: 0x" << std::hex << syscallHash << std::dec << "\n";

    PBYTE funcAddress = (PBYTE)GetProcAddressByHash(hNtdll, syscallHash);
    if(!funcAddress) {
        std::cout << "[-] Failed to get export address for hash 0x" << std::hex << syscallHash << std::dec << "\n";
        return entry;
    }

    // Expected syscall stub prologue
    if (funcAddress[0] == 0x4C && funcAddress[1] == 0x8B && funcAddress[2] == 0xD1 && funcAddress[3] == 0xB8) {
        entry.SSN = *(DWORD*)(&funcAddress[4]);
        entry.Gadget = (ULONG_PTR)FindSyscallAddressInFunction(funcAddress);
        std::cout << "[+] Clean stub detected. SSN: " << entry.SSN << "\n";
        return entry;
    }
    
    // Modified / redirected syscall stub
    if (funcAddress[0] == 0xE9 || funcAddress[0] == 0xCC) {
        std::cout << "[!] Hook detected (opcode 0x" << std::hex << (int)funcAddress[0] << std::dec << ")! Searching nearby stubs...\n";
        
        for (WORD idx = 1; idx < 32; idx++) {
            // Search upwards in memory
            PBYTE bgFuncAddress = funcAddress - (idx * 32);
            if (bgFuncAddress[0] == 0x4C && bgFuncAddress[1] == 0x8B && bgFuncAddress[2] == 0xD1 && bgFuncAddress[3] == 0xB8) {
                entry.SSN = *(DWORD*)(&bgFuncAddress[4]) + idx;
                entry.Gadget = (ULONG_PTR)FindSyscallAddressInFunction(bgFuncAddress);
                std::cout << "[+] SSN resolved from preceding stub: "
                        << entry.SSN << " (offset: +" << idx << ")\n";
                return entry;
            }

            // Search downwards in memory
            PBYTE fgFuncAddress = funcAddress + (idx * 32);
            if (fgFuncAddress[0] == 0x4C && fgFuncAddress[1] == 0x8B && fgFuncAddress[2] == 0xD1 && fgFuncAddress[3] == 0xB8) {
                entry.SSN = *(DWORD*)(&fgFuncAddress[4]) - idx;
                entry.Gadget = (DWORD64)FindSyscallAddressInFunction(fgFuncAddress);
                std::cout << "[+] SSN resolved from following stub: "
                        << entry.SSN << " (offset: -" << idx << ")\n";
                return entry;
            }
        }
    }

    std::cout << "[-] Failed to parse syscall SSN and gadget!\n";
    return entry;
}

BOOL initIndirectSyscalls() {
    std::cout << "[*] Initializing Indirect Syscalls subsystem...\n";
    
    g_Ntdll = GetModuleByHash(HASHW(L"ntdll.dll"));
    if(!g_Ntdll) {
        std::cout << "[-] Critical Error: Can't find ntdll.dll in PEB!\n";
        return FALSE;
    }

    g_Sys.NtQueryInformationProcess = GetSyscallData(HASH("NtQueryInformationProcess"), g_Ntdll);
    if(g_Sys.NtQueryInformationProcess.SSN == 0 || g_Sys.NtQueryInformationProcess.Gadget == 0) {
        std::cout << "[-] Critical Error: Failed to initialize NtQueryInformationProcess syscall data.\n";
        return FALSE;
    }

    std::cout << "[+] Indirect Syscalls successfully initialized!\n\n";
    return TRUE;
}

NTSTATUS SysNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    SYSCALL_CONTEXT ctx;
    ctx.Ssn = g_Sys.NtQueryInformationProcess.SSN;
    ctx.GadgetAddress = g_Sys.NtQueryInformationProcess.Gadget;
    ctx.rcx  = (ULONG_PTR)ProcessHandle;
    ctx.rdx  = (ULONG_PTR)ProcessInformationClass;
    ctx.r8   = (ULONG_PTR)ProcessInformation;
    ctx.r9   = (ULONG_PTR)ProcessInformationLength;
    ctx.Arg5 = (ULONG_PTR)ReturnLength;

    std::cout << "[>] Executing indirect syscall NtQueryInformationProcess:\n";
    std::cout << "    |-- SSN:         " << ctx.Ssn << "\n";
    std::cout << "    |-- Gadget:      " << (void*)ctx.GadgetAddress << "\n";
    std::cout << "    |-- Process:     " << (void*)ProcessHandle << "\n";
    std::cout << "    |-- Class:       " << (int)ProcessInformationClass << "\n";

    NTSTATUS status = UniversalSyscall(&ctx);

    std::cout << "    |-- Status:      0x" << std::hex << status << std::dec << "\n";
    return status;
}