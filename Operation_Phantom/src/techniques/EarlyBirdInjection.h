#ifndef EARLY_BIRD_INJECTION_H
#define EARLY_BIRD_INJECTION_H

#include <string>
#include <vector>
#include <windows.h>
#include "I_InjectionTechnique.h"

class EarlyBirdInjection : public I_InjectionTechnique {
public:
    explicit EarlyBirdInjection(HMODULE hNtdll);
    ~EarlyBirdInjection() override;

    InjectionResult inject(
        const std::string& processName,
        const std::vector<unsigned char>& payloadBundle,
        size_t codeOffset) override;

    const char* getName() const override { return "Early Bird Injection (SetThreadContext)"; }

private:
    HMODULE hNtdll;
};

#endif // EARLY_BIRD_INJECTION_H 