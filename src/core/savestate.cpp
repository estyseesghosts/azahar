// Copyright 2020-2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv3 or any later version
// Refer to the LICENSE.txt file included.

#include <atomic>
#include <chrono>
#include <span>
#include <sstream>
#include <streambuf>
#include <cryptopp/hex.h>
#include <fmt/ranges.h>
#include "common/archives.h"
#include "common/file_util.h"
#include "common/logging/log.h"
#include "common/scm_rev.h"
#include "common/swap.h"
#include "common/zstd_compression.h"
#include "core/core.h"
#include "core/loader/loader.h"
#include "core/movie.h"
#include "core/savestate.h"
#include "network/network.h"

namespace Core {

#pragma pack(push, 1)
struct CSTHeader {
    std::array<u8, 4> filetype{};    /// Unique Identifier to check the file type (always "CST"0x1B)
    u64_le program_id{};             /// ID of the ROM being executed. Also called title_id
    std::array<u8, 20> revision{};   /// Git hash of the revision this savestate was created with
    u64_le time{};                   /// The time when this save state was created
    std::array<u8, 20> build_name{}; /// The build name (Canary/Nightly) with the version number
    u32_le zero{};                   /// Should be zero, just in case.
    std::array<u8, 20> build_version{}; /// Latest build version, used as compatibility.
    u32_le zero_2{};                    /// Should be zero, just in case.

    std::array<u8, 168> reserved{}; /// Make heading 256 bytes so it has consistent size
};
static_assert(sizeof(CSTHeader) == 256, "CSTHeader should be 256 bytes");
#pragma pack(pop)

constexpr std::array<u8, 4> header_magic_bytes{{'C', 'S', 'T', 0x1B}};

static std::string GetSaveStatePath(u64 program_id, u64 movie_id, u32 slot) {
    if (movie_id) {
        return fmt::format("{}{:016X}.movie{:016X}.{:02d}.cst",
                           FileUtil::GetUserPath(FileUtil::UserPath::StatesDir), program_id,
                           movie_id, slot);
    } else {
        return fmt::format("{}{:016X}.{:02d}.cst",
                           FileUtil::GetUserPath(FileUtil::UserPath::StatesDir), program_id, slot);
    }
}

static bool ValidateSaveState(const CSTHeader& header, SaveStateInfo& info, u64 program_id,
                              u64 movie_id) {
    const auto path = GetSaveStatePath(program_id, movie_id, info.slot);
    if (header.filetype != header_magic_bytes) {
        LOG_WARNING(Core, "Invalid save state file {}", path);
        return false;
    }
    info.time = header.time;

    if (header.program_id != program_id) {
        LOG_WARNING(Core, "Save state file isn't for the current game {}", path);
        return false;
    }
    const std::string revision = fmt::format("{:02x}", fmt::join(header.revision, ""));
    const std::string build_name =
        header.zero == 0 ? reinterpret_cast<const char*>(header.build_name.data()) : "";
    const std::string build_version =
        header.zero_2 == 0 ? reinterpret_cast<const char*>(header.build_version.data()) : "";

    if (revision == Common::g_scm_rev) {
        info.status = SaveStateInfo::ValidationStatus::OK;
    } else {
        info.build_name = build_name;
        info.build_version = build_version;

        info.status = Common::g_build_version == info.build_version
                          ? SaveStateInfo::ValidationStatus::RevisionMismatch
                          : SaveStateInfo::ValidationStatus::BuildMismatch;
    }
    return true;
}

std::vector<SaveStateInfo> ListSaveStates(u64 program_id, u64 movie_id) {
    std::vector<SaveStateInfo> result;
    result.reserve(SaveStateSlotCount);
    for (u32 slot = 0; slot <= SaveStateSlotCount; ++slot) {
        const auto path = GetSaveStatePath(program_id, movie_id, slot);
        if (!FileUtil::Exists(path)) {
            continue;
        }

        SaveStateInfo info;
        info.slot = slot;

        FileUtil::IOFile file(path, "rb");
        if (!file) {
            LOG_ERROR(Core, "Could not open file {}", path);
            continue;
        }
        CSTHeader header;
        if (file.GetSize() < sizeof(header)) {
            LOG_ERROR(Core, "File too small {}", path);
            continue;
        }
        if (file.ReadBytes(&header, sizeof(header)) != sizeof(header)) {
            LOG_ERROR(Core, "Could not read from file {}", path);
            continue;
        }
        if (!ValidateSaveState(header, info, program_id, movie_id)) {
            continue;
        }

        result.emplace_back(std::move(info));
    }
    return result;
}

SaveStateInfo GetSaveStateInfo(u64 program_id, u64 movie_id, u32 slot) {
    SaveStateInfo info{};
    info.slot = std::numeric_limits<u32>::max();

    const auto path = GetSaveStatePath(program_id, movie_id, slot);
    if (!FileUtil::Exists(path)) {
        return info;
    }

    FileUtil::IOFile file(path, "rb");
    if (!file) {
        LOG_ERROR(Core, "Could not open file {}", path);
        return info;
    }
    CSTHeader header;
    if (file.GetSize() < sizeof(header)) {
        LOG_ERROR(Core, "File too small {}", path);
        return info;
    }
    if (file.ReadBytes(&header, sizeof(header)) != sizeof(header)) {
        LOG_ERROR(Core, "Could not read from file {}", path);
        return info;
    }
    if (ValidateSaveState(header, info, program_id, movie_id)) {
        info.slot = slot;
    }
    return info;
}

void System::SaveState(u32 slot) const {
    if (app_loader) {
        if (!app_loader->SupportsSaveStates()) {
            throw std::runtime_error("Savestates are not supported by the current application "
                                     "loader (Artic Base).");
        }
    }

    std::ostringstream sstream{std::ios_base::binary};
    // Serialize
    oarchive oa{sstream};
    oa&* this;

    const std::string& str{sstream.str()};
    const auto data = std::span<const u8>{reinterpret_cast<const u8*>(str.data()), str.size()};
    auto buffer = Common::Compression::CompressDataZSTDDefault(data);

    const u64 movie_id = movie.GetCurrentMovieID();
    const auto path = GetSaveStatePath(title_id, movie_id, slot);
    if (!FileUtil::CreateFullPath(path)) {
        throw std::runtime_error("Could not create path " + path);
    }

    FileUtil::IOFile file(path, "wb");
    if (!file) {
        throw std::runtime_error("Could not open file " + path);
    }

    CSTHeader header{};
    header.filetype = header_magic_bytes;
    header.program_id = title_id;
    std::string rev_bytes;
    CryptoPP::StringSource ss(Common::g_scm_rev, true,
                              new CryptoPP::HexDecoder(new CryptoPP::StringSink(rev_bytes)));
    std::memcpy(header.revision.data(), rev_bytes.data(), sizeof(header.revision));
    header.time = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    const std::string build_fullname = Common::g_build_fullname;
    std::memset(header.build_name.data(), 0, sizeof(header.build_name));
    std::memcpy(header.build_name.data(), build_fullname.c_str(),
                std::min(build_fullname.length(), sizeof(header.build_name) - 1));

    if (file.WriteBytes(&header, sizeof(header)) != sizeof(header) ||
        file.WriteBytes(buffer.data(), buffer.size()) != buffer.size()) {
        throw std::runtime_error("Could not write to file " + path);
    }
}

void System::LoadState(u32 slot) {
    if (app_loader) {
        if (!app_loader->SupportsSaveStates()) {
            throw std::runtime_error("Savestates are not supported by the current application "
                                     "loader (Artic Base)");
        }
    }
    auto room_member = Network::GetRoomMember().lock();
    if (room_member && room_member->IsConnected()) {
        throw std::runtime_error("Unable to load while connected to multiplayer");
    }

    const u64 movie_id = movie.GetCurrentMovieID();
    const auto path = GetSaveStatePath(title_id, movie_id, slot);

    std::vector<u8> decompressed;
    {
        std::vector<u8> buffer(FileUtil::GetSize(path) - sizeof(CSTHeader));

        FileUtil::IOFile file(path, "rb");

        // load header
        CSTHeader header;
        if (file.ReadBytes(&header, sizeof(header)) != sizeof(header)) {
            throw std::runtime_error("Could not read from file at " + path);
        }

        // validate header
        SaveStateInfo info;
        info.slot = slot;
        if (!ValidateSaveState(header, info, title_id, movie_id) ||
            info.status == SaveStateInfo::ValidationStatus::BuildMismatch) {
            throw std::runtime_error("Invalid savestate");
        }

        if (file.ReadBytes(buffer.data(), buffer.size()) != buffer.size()) {
            throw std::runtime_error("Could not read from file at " + path);
        }
        decompressed = Common::Compression::DecompressDataZSTD(buffer);
    }
    std::istringstream sstream{
        std::string{reinterpret_cast<char*>(decompressed.data()), decompressed.size()},
        std::ios_base::binary};
    decompressed.clear();

    // Deserialize
    iarchive ia{sstream};
    ia&* this;
}

namespace {
// Output stream over a vector, so serialization needs no std::string copy afterwards.
class VectorWriteBuffer final : public std::streambuf {
public:
    explicit VectorWriteBuffer(std::vector<u8>& out) : out(out) {}

protected:
    int_type overflow(int_type c) override {
        if (!traits_type::eq_int_type(c, traits_type::eof()))
            out.push_back(static_cast<u8>(c));
        return traits_type::not_eof(c);
    }
    std::streamsize xsputn(const char* data, std::streamsize count) override {
        out.insert(out.end(), reinterpret_cast<const u8*>(data),
                   reinterpret_cast<const u8*>(data) + count);
        return count;
    }

private:
    std::vector<u8>& out;
};

// Read-only stream over existing bytes, so deserialization needs no std::string copy.
class SpanReadBuffer final : public std::streambuf {
public:
    explicit SpanReadBuffer(std::span<const u8> bytes) {
        char* begin = const_cast<char*>(reinterpret_cast<const char*>(bytes.data()));
        setg(begin, begin, begin + bytes.size());
    }
};

// Last serialized size: reserving it avoids repeated reallocation while serializing.
std::atomic<std::size_t> last_serialized_size{0};

u64 Nanoseconds(std::chrono::steady_clock::time_point since) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() -
                                                                since)
        .count();
}
} // namespace

std::vector<u8> System::SaveStateBuffer() const {
    return SaveStateBuffer(Common::Compression::DefaultCompressionLevel(), nullptr);
}

void System::SerializeState(std::vector<u8>& out) const {
    out.clear();
    out.reserve(last_serialized_size.load(std::memory_order_relaxed));
    {
        VectorWriteBuffer buffer{out};
        std::ostream stream{&buffer};
        oarchive oa{stream};
        oa&* this;
    }
    last_serialized_size.store(out.size(), std::memory_order_relaxed);
}

std::array<u8, 256> System::StateHeader() const {
    CSTHeader header{};
    header.filetype = header_magic_bytes;
    header.program_id = title_id;
    std::string rev_bytes;
    CryptoPP::StringSource ss(Common::g_scm_rev, true,
                              new CryptoPP::HexDecoder(new CryptoPP::StringSink(rev_bytes)));
    std::memcpy(header.revision.data(), rev_bytes.data(), sizeof(header.revision));
    header.time = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
    const std::string build_fullname = Common::g_build_fullname;
    std::memset(header.build_name.data(), 0, sizeof(header.build_name));
    std::memcpy(header.build_name.data(), build_fullname.c_str(),
                std::min(build_fullname.length(), sizeof(header.build_name) - 1));

    const std::string build_version = Common::g_build_version;
    std::memset(header.build_version.data(), 0, sizeof(header.build_version));
    std::memcpy(header.build_version.data(), build_version.c_str(),
                std::min(build_version.length(), sizeof(header.build_version) - 1));

    std::array<u8, 256> bytes;
    std::memcpy(bytes.data(), &header, sizeof(header));
    return bytes;
}

std::vector<u8> System::CompressState(std::span<const u8> header, std::span<const u8> serialized,
                                      int compression_level) {
    return Common::Compression::CompressDataZSTDAfter(header, serialized, compression_level);
}

std::vector<u8> System::SaveStateBuffer(int compression_level, SaveStateTiming* timing) const {
    const auto serialize_start = std::chrono::steady_clock::now();
    std::vector<u8> serialized;
    SerializeState(serialized);
    const u64 serialize_ns = Nanoseconds(serialize_start);

    const auto header = StateHeader();
    const auto compress_start = std::chrono::steady_clock::now();
    auto result = CompressState(header, serialized, compression_level);
    if (timing) {
        *timing = {serialize_ns, Nanoseconds(compress_start), serialized.size()};
    }
    return result;
}

void System::SerializeSections(std::vector<u8>& out,
                               std::vector<std::pair<const char*, std::size_t>>& marks) {
    out.clear();
    marks.clear();
    out.reserve(last_serialized_size.load(std::memory_order_relaxed));
    // VectorWriteBuffer has no put area, so out.size() is exact at every mark.
    serialize_mark = [&](const char* section) { marks.emplace_back(section, out.size()); };
    try {
        VectorWriteBuffer buffer{out};
        std::ostream stream{&buffer};
        oarchive oa{stream};
        oa&* this;
    } catch (...) {
        serialize_mark = nullptr;
        throw;
    }
    serialize_mark = nullptr;
}

bool System::LoadStateBuffer(std::vector<u8> buffer) {
    return LoadStateBuffer(std::span<const u8>{buffer});
}

bool System::LoadStateBuffer(std::span<const u8> buffer) {
    CSTHeader header;

    if (buffer.size() < sizeof(header)) {
        LOG_ERROR(Core, "Save state too small");
        return false;
    }

    std::memcpy(&header, buffer.data(), sizeof(header));

    if (header.filetype != header_magic_bytes) {
        LOG_ERROR(Core, "Invalid save state");
        return false;
    }

    if (header.program_id != title_id) {
        LOG_ERROR(Core, "Save state isn't for the current game");
        return false;
    }
    std::string revision = fmt::format("{:02x}", fmt::join(header.revision, ""));
    if (revision != Common::g_scm_rev) {
        LOG_ERROR(Core,
                  "Save state file created from a different revision (core: {}, savestate: {})",
                  Common::g_scm_rev, revision);
        return false;
    }

    const auto decompressed =
        Common::Compression::DecompressDataZSTD(buffer.subspan(sizeof(CSTHeader)));
    return LoadStateSerialized(decompressed);
}

bool System::LoadStateSerialized(std::span<const u8> serialized) {
    SpanReadBuffer source{serialized};
    std::istream stream{&source};

    // Deserialize
    iarchive ia{stream};
    ia&* this;

    return true;
}

} // namespace Core
