// Native process frontend. No Qt, SDL, Libretro or product-layer dependencies.
#include <chrono>
#include <iostream>
#include <string_view>
#include "core/core.h"
#include "ctr_worker/control.h"
#include "ctr_worker/frames.h"
#include "ctr_worker/frontend.h"
#ifdef _WIN32
#include <objbase.h>
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    struct ComApartment {
        HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        ~ComApartment(){if(SUCCEEDED(result))CoUninitialize();}
    } apartment;
    if(FAILED(apartment.result) && apartment.result!=RPC_E_CHANGED_MODE) {
        std::cerr<<"worker COM initialization failed\n";return 2;
    }
#endif
    if (argc == 2 && std::string_view{argv[1]} == "--self-test") {
        AudioCore::WorkerSink::Reset();
        AudioCore::WorkerSink sink;
        std::vector<s16> samples(80000, 123);
        AudioCore::WorkerSink::Record(samples.data(), 40000);
        const auto audio = AudioCore::WorkerSink::Drain();
        if (audio.samples != 40000 || audio.buffered != 16384 || audio.dropped != 23616 ||
            AudioCore::WorkerSink::Drain().buffered != 0)
            return 1;
        CtrWorker::InputState state;
        CtrWorker::Button button{state, 0};
        CtrWorker::Touch touch{state};
        state.buttons = 1;
        state.touch = true;
        state.x = 0.5f;
        state.y = 0.5f;
        if (!button.GetStatus() || !std::get<2>(touch.GetStatus()))
            return 1;
        state = {};
        if (button.GetStatus() || std::get<2>(touch.GetStatus()))
            return 1;
        std::cout << "input_disconnect_and_bounded_audio=ok\n";
        return 0;
    }
    if (argc == 1) {
        const auto* root = std::getenv("LOTUS_STORAGE_ROOT");
        if (!root || !*root) {
            std::cerr << "LOTUS_STORAGE_ROOT is required\n";
            return 2;
        }
        return CtrWorker::Control{root}.Run();
    }
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
        std::cout << "presented_frames=" << window.frames
                  << " result=" << static_cast<unsigned>(result)
                  << " unsupported_applet=" << unsupported << std::endl;
        if (window.frames >= 60)
            std::cout << CtrWorker::Capture(system, argv[3], 1, window.frames).dump() << std::endl;
        if (system.IsPoweredOn())
            system.Shutdown();
        Common::Log::Stop();
        return result == Core::System::ResultStatus::Success && window.frames >= 60 && !unsupported
                   ? 0
                   : 1;
    }
    std::cerr
        << "usage: ctr-worker --version | --probe-core | --boot <homebrew.3dsx> <private-root>\n";
    return 2;
}
