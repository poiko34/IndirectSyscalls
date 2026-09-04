#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "IndirectSyscalls.h"

int main() {
    if(!initIndirectSyscalls()) {
        std::cout << "[-] Init indirect syscalls failed" << std::endl;
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength = 0;

    NTSTATUS status = SysNtQueryInformationProcess(
        (HANDLE)-1,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status >= 0) {
        std::cout << "[+] NtQueryInformationProcess SUCCESS!\n";
        std::cout << "    Exit Status:     " << pbi.ExitStatus << "\n";
        std::cout << "    PEB Address:     " << pbi.PebBaseAddress << "\n";
        std::cout << "    Affinity Mask:   " << pbi.AffinityMask << "\n";
        std::cout << "    Base Priority:   " << pbi.BasePriority << "\n";
        std::cout << "    Process ID:      " << pbi.UniqueProcessId << "\n";
        std::cout << "    Parent PID:      " << pbi.InheritedFromUniqueProcessId << "\n";
    } else {
        std::cout << "[-] NtQueryInformationProcess failed with NTSTATUS: 0x" 
                  << std::hex << status << std::dec << "\n";
    }

    return 0;
}