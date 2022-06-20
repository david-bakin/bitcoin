#include <special.h>

#include <policy/policy.h>
#include <script/script_error.h>

#include <algorithm>
#include <experimental/source_location>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <cxxabi.h>   // for __cxa_demangle
#include <execinfo.h> // for backtrace(3)
#include <elfutils/libdwfl.h>
#include <unistd.h>   // for gitpid(2)

using namespace std::string_view_literals;

#define XSTr(s) STr(s)
#define STr(s) #s

namespace dsb {

static char const * const WORKSPACE_PATHS_RAW = R"(
src
src/.libs
src/common
src/compat
src/consensus
src/consensus/.libs
src/crc32c/src
src/crypto
src/crypto/.libs
src/index
src/init
src/interfaces
src/kernel
src/leveldb/db
src/leveldb/helpers/memenv
src/leveldb/table
src/leveldb/util
src/minisketch/src
src/minisketch/src/fields
src/node
src/policy
src/primitives
src/primitives/.libs
src/rpc
src/script
src/script/.libs
src/secp256k1/src
src/support
src/support/.libs
src/test
src/test/util
src/univalue/lib
src/univalue/lib/.libs
src/univalue/test
src/util
src/util/.libs
src/wallet
src/wallet/rpc
src/wallet/test
src/zmq
.debug
/usr/lib/debug)";

std::string pathify(std::string_view sv)
{
    std::string r{sv};
    std::transform(r.begin(), r.end(), r.begin(), [](char c){ return c == '\n' ? ':' : c; });
    return r;
}

static std::string WORKSPACE_PATHS{pathify(WORKSPACE_PATHS_RAW)};
static char* debug_info_path = WORKSPACE_PATHS.data();

std::unique_ptr<::Dwfl, decltype(&::dwfl_end)> open_dwfl()
{

    static ::Dwfl_Callbacks callbacks{};
    callbacks.debuginfo_path = &debug_info_path;
    callbacks.find_debuginfo = ::dwfl_standard_find_debuginfo;
    callbacks.find_elf = ::dwfl_linux_proc_find_elf;
    callbacks.section_address = ::dwfl_offline_section_address; // ??, or maybe dwfl_linux_kernel_module_section_address ?

    return std::unique_ptr<::Dwfl, decltype(&::dwfl_end)>(::dwfl_begin(&callbacks), ::dwfl_end);
}

std::unique_ptr<std::ostringstream> poss;

static constexpr auto barrier = "―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――";

void emit_general_information()
{
    std::string pic_value{"__PIC__ = "};
#if defined(__PIC__)
    pic_value += XSTr(__PIC__);
#else
    pic_value += "undefined";
#endif
    std::string pie_value{"__PIE__ = "};
#if defined(__PIE__)
    pie_value += XSTr(__PIE__);
#else
    pie_value += "undefined";
#endif

    std::string dwfl_version_str{};
    {
        auto session{open_dwfl()};
        if (session) {
            dwfl_version_str = dwfl_version(session.get());
        } else {
            dwfl_version_str = "<LIBDWFL DID NOT INITIALIZE>";
        }
    }

    *poss << "libdwfl version " << dwfl_version_str << ", " << pic_value << ", " << pie_value
         << " debug info path " << WORKSPACE_PATHS << "\n\n";
}


#undef STr
#undef XSTr

bool is_enabled() { return (bool)poss; }

void set_enabled(bool b)
{
    if (poss && !b) *poss << barrier << '\n' << '\n';
    poss = b ? std::make_unique<std::ostringstream>() : nullptr;
    if (b) {
        *poss << '\n' << barrier << '\n' << '\n';
        emit_general_information();
    }
}

std::ostream& oss() { return *poss.get(); }

std::string oss_contents() { return poss->str(); }

std::ostream& out_to(std::ostream& os, const srcloc loc)
{
    return os << loc.function_name() << "@(" << loc.line() << "): ";
}

std::ostream& wrap_trace(std::ostream& os, size_t indent)
{
    static constexpr auto blanks{"                                                                                                                               "};
    os << '\n';
    os << std::string_view(blanks, indent);
    return os;
}

const std::map<std::string_view, unsigned int> mapFlagNames = {
    {"P2SH"sv, (unsigned int)SCRIPT_VERIFY_P2SH},
    {"STRICTENC"sv, (unsigned int)SCRIPT_VERIFY_STRICTENC},
    {"DERSIG"sv, (unsigned int)SCRIPT_VERIFY_DERSIG},
    {"LOW_S"sv, (unsigned int)SCRIPT_VERIFY_LOW_S},
    {"SIGPUSHONLY"sv, (unsigned int)SCRIPT_VERIFY_SIGPUSHONLY},
    {"MINIMALDATA"sv, (unsigned int)SCRIPT_VERIFY_MINIMALDATA},
    {"NULLDUMMY"sv, (unsigned int)SCRIPT_VERIFY_NULLDUMMY},
    {"DISCOURAGE_UPGRADABLE_NOPS"sv, (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
    {"CLEANSTACK"sv, (unsigned int)SCRIPT_VERIFY_CLEANSTACK},
    {"MINIMALIF"sv, (unsigned int)SCRIPT_VERIFY_MINIMALIF},
    {"NULLFAIL"sv, (unsigned int)SCRIPT_VERIFY_NULLFAIL},
    {"CHECKLOCKTIMEVERIFY"sv, (unsigned int)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
    {"CHECKSEQUENCEVERIFY"sv, (unsigned int)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY},
    {"WITNESS"sv, (unsigned int)SCRIPT_VERIFY_WITNESS},
    {"DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"sv, (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM},
    {"WITNESS_PUBKEYTYPE"sv, (unsigned int)SCRIPT_VERIFY_WITNESS_PUBKEYTYPE},
    {"CONST_SCRIPTCODE"sv, (unsigned int)SCRIPT_VERIFY_CONST_SCRIPTCODE},
    {"TAPROOT"sv, (unsigned int)SCRIPT_VERIFY_TAPROOT},
    {"DISCOURAGE_UPGRADABLE_PUBKEYTYPE"sv, (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE},
    {"DISCOURAGE_OP_SUCCESS"sv, (unsigned int)SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS},
    {"DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"sv, (unsigned int)SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION},
};

// Check that all flags in STANDARD_SCRIPT_VERIFY_FLAGS are present in mapFlagNames
[[maybe_unused]] auto DoValidateMapFlagNames = []() {
    unsigned int standard_flags_missing{STANDARD_SCRIPT_VERIFY_FLAGS};
    for (const auto& pair : mapFlagNames) {
        standard_flags_missing &= ~(pair.second);
    }
    assert(!standard_flags_missing && "array `mapFlagNames` is missing a script verification flag");
    return true;
}();

struct ScriptErrorDesc {
    ScriptError_t err;
    const std::string_view name;
};

const ScriptErrorDesc script_errors[] = {
    {SCRIPT_ERR_OK, "OK"sv},
    {SCRIPT_ERR_UNKNOWN_ERROR, "UNKNOWN_ERROR"sv},
    {SCRIPT_ERR_EVAL_FALSE, "EVAL_FALSE"sv},
    {SCRIPT_ERR_OP_RETURN, "OP_RETURN"sv},
    {SCRIPT_ERR_SCRIPT_SIZE, "SCRIPT_SIZE"sv},
    {SCRIPT_ERR_PUSH_SIZE, "PUSH_SIZE"sv},
    {SCRIPT_ERR_OP_COUNT, "OP_COUNT"sv},
    {SCRIPT_ERR_STACK_SIZE, "STACK_SIZE"sv},
    {SCRIPT_ERR_SIG_COUNT, "SIG_COUNT"sv},
    {SCRIPT_ERR_PUBKEY_COUNT, "PUBKEY_COUNT"sv},
    {SCRIPT_ERR_VERIFY, "VERIFY"sv},
    {SCRIPT_ERR_EQUALVERIFY, "EQUALVERIFY"sv},
    {SCRIPT_ERR_CHECKMULTISIGVERIFY, "CHECKMULTISIGVERIFY"sv},
    {SCRIPT_ERR_CHECKSIGVERIFY, "CHECKSIGVERIFY"sv},
    {SCRIPT_ERR_NUMEQUALVERIFY, "NUMEQUALVERIFY"sv},
    {SCRIPT_ERR_BAD_OPCODE, "BAD_OPCODE"sv},
    {SCRIPT_ERR_DISABLED_OPCODE, "DISABLED_OPCODE"sv},
    {SCRIPT_ERR_INVALID_STACK_OPERATION, "INVALID_STACK_OPERATION"sv},
    {SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, "INVALID_ALTSTACK_OPERATION"sv},
    {SCRIPT_ERR_UNBALANCED_CONDITIONAL, "UNBALANCED_CONDITIONAL"sv},
    {SCRIPT_ERR_NEGATIVE_LOCKTIME, "NEGATIVE_LOCKTIME"sv},
    {SCRIPT_ERR_UNSATISFIED_LOCKTIME, "UNSATISFIED_LOCKTIME"sv},
    {SCRIPT_ERR_SIG_HASHTYPE, "SIG_HASHTYPE"sv},
    {SCRIPT_ERR_SIG_DER, "SIG_DER"sv},
    {SCRIPT_ERR_MINIMALDATA, "MINIMALDATA"sv},
    {SCRIPT_ERR_SIG_PUSHONLY, "SIG_PUSHONLY"sv},
    {SCRIPT_ERR_SIG_HIGH_S, "SIG_HIGH_S"sv},
    {SCRIPT_ERR_SIG_NULLDUMMY, "SIG_NULLDUMMY"sv},
    {SCRIPT_ERR_PUBKEYTYPE, "PUBKEYTYPE"sv},
    {SCRIPT_ERR_CLEANSTACK, "CLEANSTACK"sv},
    {SCRIPT_ERR_MINIMALIF, "MINIMALIF"sv},
    {SCRIPT_ERR_SIG_NULLFAIL, "NULLFAIL"sv},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS, "DISCOURAGE_UPGRADABLE_NOPS"sv},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM"sv},
    {SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH, "WITNESS_PROGRAM_WRONG_LENGTH"sv},
    {SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY, "WITNESS_PROGRAM_WITNESS_EMPTY"sv},
    {SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH, "WITNESS_PROGRAM_MISMATCH"sv},
    {SCRIPT_ERR_WITNESS_MALLEATED, "WITNESS_MALLEATED"sv},
    {SCRIPT_ERR_WITNESS_MALLEATED_P2SH, "WITNESS_MALLEATED_P2SH"sv},
    {SCRIPT_ERR_WITNESS_UNEXPECTED, "WITNESS_UNEXPECTED"sv},
    {SCRIPT_ERR_WITNESS_PUBKEYTYPE, "WITNESS_PUBKEYTYPE"sv},
    {SCRIPT_ERR_OP_CODESEPARATOR, "OP_CODESEPARATOR"sv},
    {SCRIPT_ERR_SIG_FINDANDDELETE, "SIG_FINDANDDELETE"sv},
    {SCRIPT_ERR_DISCOURAGE_OP_SUCCESS, "DISCOURAGE_OP_SUCCESS"sv},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"sv},
    {SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION, "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"sv},
    {SCRIPT_ERR_SCHNORR_SIG, "SCHNORR_SIG"sv},
    {SCRIPT_ERR_SCHNORR_SIG_HASHTYPE, "SCHNORR_SIG_HASHTYPE"sv},
    {SCRIPT_ERR_SCHNORR_SIG_SIZE, "SCHNORR_SIG_SIZE"sv},
    {SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE, "TAPROOT_WRONG_CONTROL_SIZE"sv},
    {SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG, "TAPSCRIPT_CHECKMULTISIG"sv},
    {SCRIPT_ERR_TAPSCRIPT_MINIMALIF, "TAPSCRIPT_MINIMALIF"sv},
    {SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, "TAPSCRIPT_VALIDATION_WEIGHT"sv},
};

// Check that all ERROR CODES in ScriptError_t are present in script_errors array
[[maybe_unused]] auto DoValidateScriptErrorCount = []() {
    assert(SCRIPT_ERR_ERROR_COUNT == std::size(script_errors));
    return true;
}();

std::string FormatScriptFlags(unsigned int flags)
{
    if (flags == 0) {
        return "";
    }
    std::string ret;
    decltype(mapFlagNames)::const_iterator it = mapFlagNames.begin();
    while (it != mapFlagNames.end()) {
        if (flags & it->second) {
            ret += it->first;
            ret += ",";
        }
        it++;
    }
    if (ret.empty()) return "";
    ret.resize(ret.size()-1);
    return ret;
}

std::string FormatScriptError(ScriptError_t err)
{
    for (const auto& se : script_errors)
        if (se.err == err)
            return std::string(se.name);
    return "<SCRIPT_ERROR_UNKNOWN>";
}

std::string diy_stacktrace()
{
    // stack trace via `backtrace(3)`, name demangling via `libdwfl`, by
    // [Ciro Santilli (Путлер Капут) (六四事) answer on how to do a stacktrace, with symbols, Linux, C++, demangled w/o Boost](https://stackoverflow.com/a/54365144/751579)

    auto no_trace = [](const std::string_view sv)
    {
        std::string r{"<NO STACKTRACE AVAILABLE - "};
        r += sv;
        r += ">";
        return r;
    };

    auto session{open_dwfl()};
    if (!session) return no_trace("couldn't open dwfl session");

    int r = ::dwfl_linux_proc_report(session.get(), ::getpid());
    if (r) {
        std::string errstr = "a call to dwfl_report_module failed (-1)";
        if (-1 != r) {
            auto err = ::dwfl_errno();
            std::ostringstream oss;
            oss << "opening proc files failed - " << ::dwfl_errmsg(err) << " (" << err << ')';
            errstr = oss.str();
        }
        errstr.replace(0, 0, "::dwfl_linux_proc_report_failed - ");
        return no_trace(errstr);
    }

    r = ::dwfl_report_end(session.get(), nullptr, nullptr);
    if (r) {
        return no_trace("::dwfl_report_end failed");
    }

    // get the stack trace itself

    auto debug_info = [&session](void* ip) -> std::string {
        auto demangle = [](std::string_view name) -> std::string {
            int status{-4};
            std::unique_ptr<char, decltype(&std::free)> res{
                abi::__cxa_demangle(name.data(), nullptr, nullptr, &status),
                std::free
            };
            if (!status) return res.get();
            // TODO: Report error code here! (might be interesting)
            return std::string(name);
        };

        uintptr_t ip2 = reinterpret_cast<uintptr_t>(ip);
        ::Dwfl_Module* module{::dwfl_addrmodule(session.get(), ip2)};
        char const* name{::dwfl_module_addrname(module, ip2)};
        std::string function{name ? demangle(name) : "<unknown-fn>"};
        int line{-1};
        std::string file{};
        if (::Dwfl_Line* dwfl_line = ::dwfl_module_getsrc(module, ip2)) {
            ::Dwarf_Addr addr;
            file = ::dwfl_lineinfo(dwfl_line, &addr, &line, nullptr, nullptr, nullptr);
            if (file.empty()) {
                auto err = ::dwfl_errno();
                std::ostringstream oss;
                oss << "dwfl_lineinfo failed - " << ::dwfl_errmsg(err) << " (" << err << ')';
                file = oss.str();
            }
        } else {
            auto err = ::dwfl_errno();
            std::ostringstream oss;
            oss << "dwfl_module_getsrc failed - " << ::dwfl_errmsg(err) << " (" << err << ')';
            file = oss.str();
        }

        {
            std::ostringstream oss;
            oss << std::setw(8) << std::setfill('0') << std::internal << ip << ' ' << function;
            if (!file.empty()) oss << " at " << file << ':' << line;
            oss << '\n';
            return oss.str();
        }
    };

    static constexpr size_t FRAMES_TO_SKIP_AT_TOS = 4;
    static constexpr size_t BT_BUF_SIZE = 250;
    void* stack[BT_BUF_SIZE];
    int nptrs = ::backtrace(stack, BT_BUF_SIZE);
    std::ostringstream oss;
    for (int i = FRAMES_TO_SKIP_AT_TOS; i < nptrs; ++i) {
        oss << (i - FRAMES_TO_SKIP_AT_TOS) << ": ";
        oss << debug_info(stack[i]);
    }

    return oss.str();
}

std::string stacktrace()
{
    return diy_stacktrace();

#if 0
    // From example of `backtrace(3)` man page
    static constexpr size_t BT_BUF_SIZE = 200;

    int nptrs{0};
    void *buffer[BT_BUF_SIZE];
    char **strings{nullptr};

    nptrs = ::backtrace(buffer, BT_BUF_SIZE);
    strings = ::backtrace_symbols(buffer, nptrs);
    if (strings) {
        std::ostringstream oss;
        for (int i = 0; i < nptrs; i++) {
            oss << strings[i] << '\n';
        }
        ::free(strings);
        return oss.str();
    } else {
        return "<NO-STACKDUMP-AVAILABLE>";
    }
#endif
}

} // namespace
