#pragma once
#include <windows.h>

#define FNV_PRIME   0x01000193
#define FNV_OFFSET  0x811c9dc5

#define HASH(str) ([]() { constexpr DWORD hash = constexpr_fnv1a(str); return hash; }())
#define HASHW(str) ([]() { constexpr DWORD hash = constexpr_fnv1a_w(str); return hash; }())

constexpr DWORD constexpr_fnv1a(const char *str) {
    DWORD hash = FNV_OFFSET;

    if (str == 0) {
        return hash;
    }

    while (*str) {
        hash ^= (unsigned char)*str;
        hash *= FNV_PRIME;
        str++;
    }

    return hash;
}
constexpr DWORD constexpr_fnv1a_w(const wchar_t *str) {
    DWORD hash = FNV_OFFSET;

    if (str == 0) {
        return hash;
    }

    while (*str) {
        wchar_t wc = *str;
        
        hash ^= (unsigned char)(wc & 0xFF);
        hash *= FNV_PRIME;

        hash ^= (unsigned char)((wc >> 8) & 0xFF);
        hash *= FNV_PRIME;

        str++;
    }

    return hash;
}
inline DWORD runtime_fnv1a(const char *str) {
    DWORD hash = FNV_OFFSET;

    if (str == 0) {
        return hash;
    }

    while (*str) {
        hash ^= (unsigned char)*str;
        hash *= FNV_PRIME;
        str++;
    }

    return hash;
}
inline DWORD runtime_fnv1a_w(const wchar_t *str) {
    DWORD hash = FNV_OFFSET;

    if (str == 0) {
        return hash;
    }

    while (*str) {
        wchar_t wc = *str;
        
        hash ^= (unsigned char)(wc & 0xFF);
        hash *= FNV_PRIME;

        hash ^= (unsigned char)((wc >> 8) & 0xFF);
        hash *= FNV_PRIME;

        str++;
    }

    return hash;
}
