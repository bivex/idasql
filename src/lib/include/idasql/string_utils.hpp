// Copyright (c) Elias Bachaalany
// SPDX-License-Identifier: MIT

/**
 * string_utils.hpp - Shared string utility functions
 */

#pragma once

#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <string>

namespace idasql {

inline std::string format_ea_hex(uint64_t ea) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%" PRIX64, ea);
    return std::string(buf);
}

inline std::string trim_copy(const std::string& s) {
    size_t begin = 0;
    size_t end = s.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(s[begin])) != 0) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(s[end - 1])) != 0) {
        --end;
    }
    return s.substr(begin, end - begin);
}

} // namespace idasql
