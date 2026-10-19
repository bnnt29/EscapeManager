#pragma once

// Small portability helpers shared by the protocol sources.

#include <cstddef>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
#define ESCAPE_HAS_EXCEPTIONS 1
#else
#define ESCAPE_HAS_EXCEPTIONS 0
#endif

namespace Escape {

// Runs f() and turns an out-of-memory exception into `onFail`. Without exceptions
// (-fno-exceptions) it simply runs f(); allocation failure then follows the
// platform's own policy. The protocol code never lets an exception escape into the
// host program's loop(): an uncaught std::bad_alloc would abort() and reboot the board.
template <class F, class R>
R guardAlloc(F f, R onFail) {
#if ESCAPE_HAS_EXCEPTIONS
  try {
    return f();
  } catch (...) {
    return onFail;
  }
#else
  (void)onFail;
  return f();
#endif
}

} // namespace Escape
