#include "key.hpp"

namespace RegistryAnalysis {

KeyHandle::KeyHandle(libregf_key_t* key) noexcept : ptr_(key) {}

KeyHandle::~KeyHandle() { reset(); }

KeyHandle::KeyHandle(KeyHandle&& other) noexcept : ptr_(other.ptr_) {
  other.ptr_ = nullptr;
}

KeyHandle& KeyHandle::operator=(KeyHandle&& other) noexcept {
  if (this != &other) {
    reset();
    ptr_ = other.ptr_;
    other.ptr_ = nullptr;
  }
  return *this;
}

libregf_key_t* KeyHandle::getPtr() const noexcept { return ptr_; }

void KeyHandle::setPtr(libregf_key_t* key) noexcept {
  reset();
  ptr_ = key;
}

libregf_key_t** KeyHandle::getAddressOfPtr() { return &ptr_; }

KeyHandle::operator bool() const noexcept { return ptr_ != nullptr; }

void KeyHandle::reset() noexcept {
  if (ptr_) {
    libregf_key_free(&ptr_, nullptr);
    ptr_ = nullptr;
  }
}

}
