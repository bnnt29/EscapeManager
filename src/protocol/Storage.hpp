#pragma once

// Persistent key/value blobs. The firmware implements this on top of NVS
// (Preferences), the simulators on files, the tests in memory. Keys are at most 15
// characters (NVS limit) of [A-Za-z0-9_].

#include <cstddef>
#include <map>
#include <string>

namespace Escape {

class BlobStorage {
public:
  virtual ~BlobStorage() {}
  // False if the key does not exist (or cannot be read).
  virtual bool read(const char *key, std::string &out) = 0;
  // False if the value could not be stored (e.g. NVS full). Must not damage the old value.
  virtual bool write(const char *key, const std::string &data) = 0;
  virtual bool erase(const char *key) = 0;
};

// RAM-backed storage with an optional capacity limit, for tests and the simulators.
class MemoryStorage : public BlobStorage {
public:
  MemoryStorage() : capacity_(0), failWrites_(false), writes_(0) {}
  bool read(const char *key, std::string &out) override {
    std::map<std::string, std::string>::const_iterator it = data_.find(key);
    if (it == data_.end()) return false;
    out = it->second;
    return true;
  }
  bool write(const char *key, const std::string &data) override {
    if (failWrites_) return false;
    if (capacity_) {
      size_t used = data.size();
      for (std::map<std::string, std::string>::const_iterator it = data_.begin(); it != data_.end(); ++it) {
        if (it->first != key) used += it->second.size();
      }
      if (used > capacity_) return false;
    }
    data_[key] = data;
    writes_++;
    return true;
  }
  bool erase(const char *key) override { return data_.erase(key) > 0; }

  void setCapacity(size_t bytes) { capacity_ = bytes; }
  void setFailWrites(bool fail) { failWrites_ = fail; }
  size_t writeCount() const { return writes_; }
  size_t keyCount() const { return data_.size(); }
  bool has(const char *key) const { return data_.find(key) != data_.end(); }

private:
  std::map<std::string, std::string> data_;
  size_t capacity_;
  bool failWrites_;
  size_t writes_;
};

} // namespace Escape
