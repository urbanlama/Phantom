#ifndef I_INJECTION_TECHNIQUE_H
#define I_INJECTION_TECHNIQUE_H

#include <string>
#include <vector>
#include <windows.h>
#include <stdexcept>
#include "InjectionResult.h"

/**
 * @class I_InjectionTechnique
 * @brief Interface für verschiedene Code-Injektionstechniken.
 * 
 * Definiert eine einheitliche Schnittstelle, um verschiedene Methoden zur Injektion
 * von Shellcode in einen Zielprozess zu kapseln. Dies ermöglicht es dem Orchestrator,
 * die Injektionsstrategie zur Laufzeit oder Compile-Zeit auszutauschen.
 */
class I_InjectionTechnique {
public:
    virtual ~I_InjectionTechnique() = default;

    /**
     * @brief Führt die Injektion des Payloads aus.
     * 
     * @param processName Der Name des Zielprozesses (z.B. "svchost.exe").
     * @param payloadBundle Ein Vektor, der die zu injizierenden Daten enthält.
     *                      Dies kann eine Kombination aus Konfigurationsdaten und Shellcode sein.
     * @param codeOffset Der Offset innerhalb des payloadBundle, an dem der ausführbare Code beginnt.
     * @return Ein InjectionResult-Wert, der den Ausgang der Operation beschreibt.
     * @throws std::runtime_error bei kritischen, nicht behebbaren Fehlern.
     */
    virtual InjectionResult inject(
        const std::string& processName, 
        const std::vector<unsigned char>& payloadBundle,
        size_t codeOffset
    ) = 0;

    /**
     * @brief Gibt den Namen der Injektionstechnik zurück.
     * @return Ein String mit dem Namen der Technik.
     */
    virtual const char* getName() const = 0;
};

#endif // I_INJECTION_TECHNIQUE_H 