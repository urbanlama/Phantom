#ifndef APC_INJECTION_H
#define APC_INJECTION_H

#include <string>
#include <vector>
#include <windows.h>
#include "I_InjectionTechnique.h"

class ApcInjection : public I_InjectionTechnique {
public:
    explicit ApcInjection(HMODULE hNtdll);
    ~ApcInjection() override;

    InjectionResult inject(
        const std::string& processName, 
        const std::vector<unsigned char>& payloadBundle,
        size_t codeOffset) override;

    const char* getName() const override { return "APC Injection (mit Indirect Syscalls)"; }

private:
    HMODULE hNtdll;
};

#endif // APC_INJECTION_H 