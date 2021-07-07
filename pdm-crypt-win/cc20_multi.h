#pragma once

/*
cc20_multi.h

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.

author:     Yi Yang
            5/2021
*/
#ifndef _cc20_multi_
#define _cc20_multi_

#include <stdio.h>
#include <chrono>
#include <iostream>
// Added 

#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>


class Cc20 {


public:

    void start_seq();
    void encr(uint8_t* line, uint8_t* linew, unsigned long int fsize);
    void rd_file_encr(const std::string file_name, std::string oufile_name);
    void stream(uint8_t* plain, unsigned int len);
    void set_vals(uint8_t* nonce, uint8_t* key);
    void one_block(int thrd, uint32_t count);
    void endicha(uint8_t* a, uint32_t* b);


    // Make sure this number is same as THREAD_COUNT
    //           *
    uint8_t nex[41][65];


private:

    uint8_t* nonce;

    uint32_t count;

    uint8_t nonce_orig[13] = { 0 };

    // Make sure this number is same as THREAD_COUNT
    //          *
    uint32_t cy[41][17];

    uint8_t* key;

    // Binary constant for chacha20 state, modified 
    unsigned long b1 = 0B01100001011100010111100011100101;
    unsigned long b2 = 0B10110111001011000110011101101110;
    unsigned long b3 = 0B01111001111000101010110100110010;
    unsigned long b4 = 0B01101011001001000110010101110100;
};
int main_c(int argc, char** argv);
void cmd_enc(std::string infile_name, std::string oufile_name, std::string text_nonce);
#endif