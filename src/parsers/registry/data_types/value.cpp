#include "value.hpp"

namespace RegistryAnalysis {

ValueHandle::ValueHandle(libregf_value_t* value) noexcept : ptr_(value) {}

ValueHandle::~ValueHandle() { reset(); }

ValueHandle::ValueHandle(ValueHandle&& other) noexcept : ptr_(other.ptr_) {
  other.ptr_ = nullptr;
}

ValueHandle& ValueHandle::operator=(ValueHandle&& other) noexcept {
  if (this != &other) {
    reset();
    ptr_ = other.ptr_;
    other.ptr_ = nullptr;
  }
  return *this;
}

libregf_value_t* ValueHandle::getPtr() const noexcept { return ptr_; }

void ValueHandle::setPtr(libregf_value_t* value) noexcept {
  reset();
  ptr_ = value;
}

libregf_value_t** ValueHandle::getAddressOfPtr() { return &ptr_; }

ValueHandle::operator bool() const noexcept { return ptr_ != nullptr; }

void ValueHandle::reset() noexcept {
  if (ptr_) {
    libregf_value_free(&ptr_, nullptr);
    ptr_ = nullptr;
  }
}

}
