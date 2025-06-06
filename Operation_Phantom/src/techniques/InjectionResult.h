#ifndef INJECTION_RESULT_H
#define INJECTION_RESULT_H

/**
 * @enum InjectionResult
 * @brief Definiert die möglichen Ergebnisse einer Injektionsoperation.
 *
 * Diese Enumeration wird von den Injektionstechniken zurückgegeben, um dem
 * Orchestrator ein detailliertes Feedback über den Erfolg oder die Art
 * des Fehlschlags zu geben.
 */
enum class InjectionResult {
    SUCCESS,                    // Die Injektion war erfolgreich.
    PROCESS_CREATION_FAILED,    // Der Zielprozess konnte nicht erstellt oder gefunden werden.
    MEMORY_ALLOCATION_FAILED,   // Speicher konnte im Zielprozess nicht alloziert werden.
    MEMORY_WRITE_FAILED,        // Die Payload konnte nicht in den Zielprozess geschrieben werden.
    API_RESOLUTION_FAILED,      // Notwendige API-Funktionen konnten nicht gefunden werden.
    INJECTION_FAILED,           // Ein allgemeiner Fehler während der Injektion (z.B. Thread-Erstellung, Context-Set).
    TECHNIQUE_NOT_SUPPORTED,    // Die Technik wird auf dem Zielsystem nicht unterstützt (z.B. x64-only).
    CLEANUP_FAILED              // Aufräumen nach einem Fehler ist fehlgeschlagen.
};

#endif // INJECTION_RESULT_H 