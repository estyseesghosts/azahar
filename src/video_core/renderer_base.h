// Copyright 2014-2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv3 or any later version
// Refer to the LICENSE.txt file included.

#pragma once
#include <array>
#include <stdexcept>

#include "common/common_types.h"
#include "core/frontend/framebuffer_layout.h"
#include "video_core/rasterizer_interface.h"

namespace Frontend {
class EmuWindow;
}

namespace Core {
class System;
}

namespace VideoCore {

enum class ScreenId : u32 {
    TopLeft,
    TopRight,
    Bottom,
};

struct RendererSettings {
    // Screenshot
    std::atomic_bool screenshot_requested{false};
    void* screenshot_bits{};
    std::function<void(bool)> screenshot_complete_callback;
    Layout::FramebufferLayout screenshot_framebuffer_layout;
    // Renderer
    std::atomic_bool bg_color_update_requested{false};
    std::atomic_bool shader_update_requested{false};
};

class RendererBase : NonCopyable {
public:
    explicit RendererBase(Core::System& system, Frontend::EmuWindow& window,
                          Frontend::EmuWindow* secondary_window);
    virtual ~RendererBase();

    /// Synchronous screenshot at an emulation safe point, without advancing a guest frame.
    virtual void CaptureOffscreen(void*, const Layout::FramebufferLayout&) {
        throw std::runtime_error("offscreen capture unsupported by renderer");
    }

    /// Counters of the live-preview readback since the renderer was created.
    struct PreviewStats {
        u64 readbacks = 0;     ///< Screen pairs whose copy was submitted.
        u64 skipped_busy = 0;  ///< Requests that submitted nothing: every slot still in flight.
        u64 stale = 0;         ///< Requests with no newer completed pair to copy.
        u64 gpu_waits = 0;     ///< Waits for the GPU, only on paused requests.
        u64 gpu_wait_ns = 0;
        u64 copied_bytes = 0;  ///< Bytes copied out of staging memory.
    };

    /// Live preview of both screens (`layouts[0]` top, `[1]` bottom) into `pixels`. Copies the
    /// newest frame whose two readbacks have completed and whose id is at least `oldest`, then
    /// submits readbacks of the current frame `frame_id`. Waits for the GPU only when
    /// `may_wait` (a paused worker, where waiting stalls no emulation); the result is then
    /// `frame_id`. Returns the id of the copied pair, or 0 when none qualifies and `pixels`
    /// were not written. The default is the synchronous capture.
    virtual u64 PreviewScreens(const std::array<void*, 2>& pixels,
                               const std::array<Layout::FramebufferLayout, 2>& layouts, u64 frame_id,
                               u64 oldest, bool may_wait) {
        CaptureOffscreen(pixels[0], layouts[0]);
        CaptureOffscreen(pixels[1], layouts[1]);
        return frame_id;
    }

    virtual PreviewStats PreviewStatistics() const {
        return {};
    }

    /// Returns the rasterizer owned by the renderer
    virtual VideoCore::RasterizerInterface* Rasterizer() = 0;

    /// Finalize rendering the guest frame and draw into the presentation texture
    virtual void SwapBuffers() = 0;

    /// Draws the latest frame to the window waiting timeout_ms for a frame to arrive (Renderer
    /// specific implementation)
    virtual void TryPresent(int timeout_ms, bool is_secondary) = 0;
    virtual void TryPresent(int timeout_ms) {
        TryPresent(timeout_ms, false);
    }

    /// Prepares for video dumping (e.g. create necessary buffers, etc)
    virtual void PrepareVideoDumping() {}

    /// Cleans up after video dumping is ended
    virtual void CleanupVideoDumping() {}

    /// This is called to notify the rendering backend of a surface change
    // if second == true then it is the second screen
    virtual void NotifySurfaceChanged(bool second) {}

    /// Returns the resolution scale factor relative to the native 3DS screen resolution
    u32 GetResolutionScaleFactor();

    /// Returns the MSAA sample count
    u8 GetSampleCount() const;

    /// Updates the framebuffer layout of the contained render window handle.
    void UpdateCurrentFramebufferLayout(bool is_portrait_mode = {});

    /// Ends the current frame
    void EndFrame();

    f32 GetCurrentFPS() const {
        return current_fps;
    }

    u64 GetCurrentFrame() const {
        return current_frame;
    }

    Frontend::EmuWindow& GetRenderWindow() {
        return render_window;
    }

    const Frontend::EmuWindow& GetRenderWindow() const {
        return render_window;
    }

    [[nodiscard]] RendererSettings& Settings() {
        return settings;
    }

    [[nodiscard]] const RendererSettings& Settings() const {
        return settings;
    }

    /// Returns true if a screenshot is being processed
    [[nodiscard]] bool IsScreenshotPending() const;

    /// Request a screenshot of the next frame
    void RequestScreenshot(void* data, std::function<void(bool)> callback,
                           const Layout::FramebufferLayout& layout);

protected:
    /// Waits until the GPU is at most one game frame behind the emulation.
    /// Called on VBlanks where the guest application submits a frame.
    virtual void LimitFramesAheadOfGpu() {}

    Core::System& system;
    RendererSettings settings;
    Frontend::EmuWindow& render_window;    /// Reference to the render window handle.
    Frontend::EmuWindow* secondary_window; /// Reference to the secondary render window handle.

protected:
    f32 current_fps = 0.0f; /// Current framerate, should be set by the renderer
    u64 current_frame = 0;  /// Current frame, should be set by the renderer

private:
    u64 limited_game_frames = 0; /// Guest frame count at the last LimitFramesAheadOfGpu call
};

} // namespace VideoCore
