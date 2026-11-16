// Native process frontend. No Qt, SDL, Libretro or product-layer dependencies.
#include <iostream>
#include <string_view>
#include <chrono>
#include "ctr_worker/frontend.h"
#include "ctr_worker/frames.h"
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
    if (argc == 4 && std::string_view{argv[1]} == "--boot") {
        auto& system = Core::System::GetInstance();
        bool unsupported = false;
        CtrWorker::Initialize(system, argv[3], unsupported);
        CtrWorker::Window window;
        auto result = system.Load(window, argv[2]);
        std::cout << "load_status=" << static_cast<unsigned>(result) << std::endl;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (result == Core::System::ResultStatus::Success && window.frames < 60 &&
               !unsupported && std::chrono::steady_clock::now() < deadline)
            result = system.RunLoop();
        std::cout << "presented_frames=" << window.frames << " result=" << static_cast<unsigned>(result)
                  << " unsupported_applet=" << unsupported << std::endl;
        if (window.frames >= 60)
            std::cout << CtrWorker::Capture(system, argv[3], 1, window.frames).dump() << std::endl;
        if (system.IsPoweredOn()) system.Shutdown();
        Common::Log::Stop();
        return result == Core::System::ResultStatus::Success && window.frames >= 60 && !unsupported ? 0 : 1;
    }
    std::cerr << "usage: ctr-worker --version | --probe-core | --boot <homebrew.3dsx> <private-root>\n";
    return 2;
}
