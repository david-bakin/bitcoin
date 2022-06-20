#include <script/script_error.h>

#include <experimental/source_location>
#include <iomanip>
#include <ostream>
#include <string_view>

namespace dsb {

using srcloc = std::experimental::source_location;

bool is_enabled();
void set_enabled(bool b = true);

std::ostream& oss();
std::ostream& out_to(std::ostream& os,
                     const srcloc loc
                        = std::experimental::source_location::current());
std::ostream& wrap_trace(std::ostream& os, size_t indent);
std::string oss_contents();

template <typename FUN> void out(FUN fun, srcloc loc) { if (is_enabled()) fun(oss(), loc); }

std::string FormatScriptFlags(unsigned int flags);
std::string FormatScriptError(ScriptError_t err);

template <typename FUN> struct guard {
    const FUN fun;
    const srcloc location;

    guard(const FUN& fn, const srcloc loc) : fun(fn), location(loc) {}
    ~guard() { fun(oss(), location); }
};

} // namespace

#define START_TRACE() {dsb::set_enabled(true);}
#define OUT(...) \
        dsb::out([&](std::ostream& os, dsb::srcloc loc) \
                            { dsb::out_to(os, loc) << __VA_ARGS__ << '\n'; }, \
                     dsb::srcloc::current());
#define WRAP(n) dsb::wrap_trace(n)
#define EXIT_OUT(...) \
        dsb::guard _x([&](std::ostream& os, dsb::srcloc loc) \
                            { if (dsb::is_enabled()) dsb::out_to(os, loc) << __VA_ARGS__ << '\n'; }, \
                         dsb::srcloc::current());
#define GET_OUT() (dsb::oss_contents())
#define STOP_TRACE() {dsb::set_enabled(false);}
#define EXIT_STOP_TRACE(fname) \
        dsb::guard _y([](std::ostream&, dsb::srcloc) \
                            { fname(dsb::oss_contents()); dsb::set_enabled(false); }, \
                          dsb::srcloc::current());


namespace dsb {

std::string stacktrace();

}
