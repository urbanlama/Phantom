#ifndef TECHNIQUE_UTIL_H
#define TECHNIQUE_UTIL_H

#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <winternl.h>

namespace Phantom {
namespace Util {

    // Compile-time DJB2a hash
    constexpr DWORD a_hash(const char* str, size_t i = 0) {
        return !str[i] ? 5381 : (a_hash(str, i + 1) * 33) ^ str[i];
    }

    // Function to get a process ID by its name
    DWORD getProcessIdByName(const std::string& processName);

    // Function to get a procedure address from a module by its hash
    PVOID getProcAddressByHash(HMODULE hModule, DWORD functionHash);

    // Find the first thread ID for a given process ID
    DWORD findFirstThreadId(DWORD processId);

} // namespace Util
} // namespace Phantom

#endif // TECHNIQUE_UTIL_H 