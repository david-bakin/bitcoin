#include <special.h>

#include <policy/policy.h>
#include <script/script_error.h>

#include <experimental/source_location>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <execinfo.h> // for backtrace(3)

using namespace std::string_view_literals;

namespace dsb {

std::unique_ptr<std::ostringstream> poss;

bool is_enabled() { return (bool)poss; }

void set_enabled(bool b) { poss = b ? std::make_unique<std::ostringstream>() : nullptr; }

std::ostream& oss() { return *poss.get(); }

std::string oss_contents() { return poss->str(); }

std::ostream& out_to(std::ostream& os, const srcloc loc)
{
    return os << loc.function_name() << "@(" << loc.line() << "): ";
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


std::string stacktrace()
{
    // From example of `backtrace(3)` man page
    static constexpr size_t BT_BUF_SIZE = 200;

    int nptrs{0};
    void *buffer[BT_BUF_SIZE];
    char **strings{nullptr};

    nptrs = ::backtrace(buffer, BT_BUF_SIZE);
    strings = ::backtrace_symbols(buffer, nptrs);
    if (strings) {
        std::string r;
        for (int i = 0; i < nptrs; i++) {
            r += strings[i];
            r += '\n';
        }
        ::free(strings);
        return r;
    } else {
        return "<NO-STACKDUMP-AVAILABLE>";
    }
}

} // namespace
