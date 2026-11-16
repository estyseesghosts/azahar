// Native process frontend. No Qt, SDL, Libretro or product-layer dependencies.
#include <iostream>
#include <string_view>
#include "core/core.h"

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--version") {
        std::cout << "ctr-worker protocol=1.0 source=" << CTR_SOURCE_SHA << '\n';
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} == "--probe-core") {
        const auto& system = Core::System::GetInstance();
        std::cout << "native_core_initialized=" << system.IsPoweredOn() << '\n';
        return 0;
    }
    std::cerr << "usage: ctr-worker --version | --probe-core\n";
    return 2;
}
