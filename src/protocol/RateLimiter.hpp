#pragma once

// Tiny token-bucket limiter: a few per-source buckets (so one noisy host cannot
// starve the others) plus a global per-second budget. About 100 bytes of state.

#include "EscapeConfig.hpp"

#include <cstdint>
#include <cstring>

namespace Escape {

class RateLimiter {
public:
  RateLimiter() : windowStart_(0), windowCount_(0) { memset(slots_, 0, sizeof(slots_)); }

  // Consumes `cost` tokens of the bucket of `source` (e.g. the IPv4 address). False if
  // the source is out of budget.
  bool allowSource(uint32_t source, uint32_t nowMs, uint8_t cost = 1) {
    Slot *slot = nullptr, *oldest = &slots_[0];
    for (uint8_t i = 0; i < EscapeConfig::RATE_SOURCES; i++) {
      if (slots_[i].used && slots_[i].source == source) slot = &slots_[i];
      if (!slots_[i].used || (int32_t)(oldest->lastMs - slots_[i].lastMs) > 0) oldest = &slots_[i];
    }
    if (!slot) { // new source: take over the least recently used slot with a full bucket
      slot = oldest;
      slot->used = true;
      slot->source = source;
      slot->tokens = EscapeConfig::RATE_BURST;
      slot->lastMs = nowMs;
    }
    const uint32_t elapsed = nowMs - slot->lastMs;
    const uint32_t gained = elapsed / EscapeConfig::RATE_REFILL_MS;
    if (gained) {
      const uint32_t total = slot->tokens + gained;
      slot->tokens = total > EscapeConfig::RATE_BURST ? EscapeConfig::RATE_BURST : (uint8_t)total;
      slot->lastMs += gained * EscapeConfig::RATE_REFILL_MS;
    }
    if (slot->tokens < cost) return false;
    slot->tokens = (uint8_t)(slot->tokens - cost);
    return true;
  }

  // At most GLOBAL_POSTS_PER_SECOND calls per second in total.
  bool allowGlobal(uint32_t nowMs) {
    if (nowMs - windowStart_ >= 1000) {
      windowStart_ = nowMs;
      windowCount_ = 0;
    }
    if (windowCount_ >= EscapeConfig::GLOBAL_POSTS_PER_SECOND) return false;
    windowCount_++;
    return true;
  }

private:
  struct Slot {
    uint32_t source;
    uint32_t lastMs;
    uint8_t tokens;
    bool used;
  };
  Slot slots_[EscapeConfig::RATE_SOURCES];
  uint32_t windowStart_;
  uint8_t windowCount_;
};

} // namespace Escape
