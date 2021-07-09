#pragma once
/*
cc20_dev.cpp

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.

author:     Yi Yang
            5/2021
*/

#include "pdm-service.hpp"
#include <ostream>
#include <wchar.h>
#include <numeric>

#ifdef DEEP_DEBUG
#include <iomanip>
#include <iostream>
#endif

#ifdef WINDOWS
#include <locale.h>
#include <windows.h>
//#include <io.h>
//#include <fcntl.h>
#endif

using namespace std;


void stream(uint8_t* key, uint8_t* nonce, uint32_t count, uint8_t* plain, unsigned int len);

#define U32T8_S(p, v)    \
  {                            \
    (p)[0] = (v >> 0) & 0xff;  \
    (p)[1] = (v >> 8) & 0xff;  \
    (p)[2] = (v >> 16) & 0xff; \
    (p)[3] = (v >> 24) & 0xff; \
  }

#define U8T32_S(p)                              \
  (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | \
   ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// INT should only be unsigned, no checks here.
template <typename NT>
void roln(NT& val, unsigned int n) {
    val = (val << n) | (val >> (8 - n));
}

template <>
void roln<uint32_t>(uint32_t& val, unsigned int n) {
    val = (val << n) | (val >> (8 - n));
}

void endicha(uint8_t* a, uint32_t* b) {
    for (unsigned int i = 0; i < 16; i++) {
        U32T8_S(a + 4 * i, b[i]);

    }
}

void expan(uint32_t* ot, unsigned int off, const uint8_t* in, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        ot[off + i] = U8T32_S(in + 4 * i);
    }
}

// Operate a quarter-round chacha state on total of 16 bytes or 4 32-bit numbers at a time.
void quarteround(uint32_t* state, uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    state[a] += state[b]; state[d] ^= state[a]; roln(state[d], 16);
    state[c] += state[d]; state[b] ^= state[c]; roln(state[b], 12);
    state[a] += state[b]; state[d] ^= state[a]; roln(state[d], 8);
    state[c] += state[d]; state[b] ^= state[c]; roln(state[b], 7);
}

void tworounds(uint32_t* state) {
    quarteround(state, 0, 4, 8, 12);
    quarteround(state, 1, 5, 9, 13);
    quarteround(state, 2, 6, 10, 14);
    quarteround(state, 3, 7, 11, 15);
    quarteround(state, 0, 5, 10, 15);
    quarteround(state, 1, 6, 11, 12);
    quarteround(state, 2, 7, 8, 13);
    quarteround(state, 3, 4, 9, 14);
}
#ifdef PRINTING
// Print a hex unsigned number
template <typename NT>
void p_hex(NT i) {
    cout << " 0x"; cout << setfill('0') << setw(8) << hex << right << i << flush;

}
template <>
void p_hex<uint8_t>(uint8_t i) {
    cout << dec << i << flush;
}

// Print a chacha state
template <typename NT>
void p_state(NT* state) {
    for (unsigned int i = 0; i < 16; i++) {
        p_hex(state[i]);
        if ((i + 1) % 4 == 0)cout << "\n";
    }
    cout << endl;
}
template <>
void p_state<uint8_t>(uint8_t* state) {
    int n = 16;
    for (unsigned int i = 0; i < 64; i++) {
        // if((i+1)%n==0)cout<<setw(1)<<right<<"\t";
        p_hex(state[i]);
        if ((i + 1) % n == 0)cout << "\n";
    }
    cout << endl;
}
#endif

template<typename NT>
void state_cpy(NT* a, NT* b, unsigned int n) {
    for (unsigned int i = 0; i < n; i++) a[i] = b[i];
}

void filterin(unsigned char* r) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}
