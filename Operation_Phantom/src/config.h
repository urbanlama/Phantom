#ifndef CONFIG_H
#define CONFIG_H

#include <array>
#include <string_view>

namespace Phantom {
namespace Obfuscation {

    // Compile-time XOR-Verschleierung für Zeichenketten
    template<std::size_t N>
    struct ObfuscatedString {
        const std::size_t size = N - 1;
        std::array<char, N> data;
        const char key;

        constexpr ObfuscatedString(const char* str, char k) : data{}, key(k) {
            for (std::size_t i = 0; i < N; ++i) {
                data[i] = str[i] ^ k;
            }
        }

        std::string decrypt() const {
            std::string decrypted_str;
            decrypted_str.resize(size);
            for (std::size_t i = 0; i < size; ++i) {
                decrypted_str[i] = data[i] ^ key;
            }
            return decrypted_str;
        }
    };

} // namespace Obfuscation
} // namespace Phantom

// --- Konfigurierbare Werte ---
namespace Phantom {
namespace Config {
    // Einfacher XOR-Schlüssel, der zur Compile-Zeit angewendet wird.
    constexpr char C2_XOR_KEY = 0x42; 
    
    // Der zu verschleiernde C2-Domainname
    // KORREKTUR: Verwende die korrekte Template-Syntax
    constexpr auto c2_domain_obf = Phantom::Obfuscation::ObfuscatedString<sizeof("your-secret-c2.com")>("your-secret-c2.com", C2_XOR_KEY);

} // namespace Config
} // namespace Phantom

#endif // CONFIG_H 