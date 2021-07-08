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



/*
cc20_multi.cpp

pdm/Personal Data Management system is a encrypted and multiplatform data searching, building, archiving tool.
This is the encryption core module for pdm.

author:     Yi Yang
            5/2021
*/

//cc20_multi.cpp    

// #ifndef BOOST_STRING_TRIM_HPP
// #define BOOST_STRING_TRIM_HPP

#include "cc20_dev.cpp"
#include "cc20_multi.h"
#include "sha3.h"
// #include <condition_variable>
// #include <boost/algorithm/string/trim.hpp>
#include <thread>


// For windows memory mapped read


#define _MBCS

#include <wchar.h>
#include <Tchar.h>
//#include <io.h>
//#include <fcntl.h>




using namespace std;
// using boost::thread;

int ENABLE_SHA3_OUTPUT = 1; // Enables sha3 output

void multi_enc_pthrd(int thrd);
void set_thread_arg(int thrd, long long int np, long long int tracker, long long int n, long long int tn, uint8_t* line, uint32_t count, Cc20* ptr);



const int BLOCK_SIZE = 4608000;
/* Invariant: BLOCK_SIZE % 64 == 0
                                 115200, 256000, 576000, 1152000,2304000,4608000,6912000,9216000 ...
                                 Block size*/

const int THREAD_COUNT = 30; // Make sure to change the header file's too.

const int PER_THREAD_BACK_LOG = 0; // This is not enabled.

uint32_t folow[THREAD_COUNT][17]; // A copy of a state.

// Statically allocates, and uses BLOCK_SIZE*THREAD_COUNT of memory. 
char thread_track[THREAD_COUNT][BLOCK_SIZE] = { {0} };

int progress_bar[THREAD_COUNT];

long long int writing_track[THREAD_COUNT]; // Tells the writer thread how much to read; should only be different on the last block.

char* linew;

long long int arg_track[THREAD_COUNT][6];
/* Passes arguments into threads.
                                       arg_track[THREAD_COUNT][0] ---> Thread number
                                       arg_track[THREAD_COUNT][1] ---> NOT USED
                                       arg_track[THREAD_COUNT][2] ---> NOT USED
                                       arg_track[THREAD_COUNT][3] ---> Remaining plain size
                                       arg_track[THREAD_COUNT][4] ---> NOT USED*/

SHA3 hashing; // A rolling hash of the input data.

uint8_t* arg_line[THREAD_COUNT]; // Addresses of memory mapped plain text from disk.

uint32_t arg_count[THREAD_COUNT]; // Count of each chacha 20 block

Cc20* arg_ptr[THREAD_COUNT]; // Parent pointers for each thread.

// recursive_mutex locks[THREAD_COUNT]; // All locks for threads, each waits for the writing is done on file or memory.

thread threads[THREAD_COUNT]; // Threads

char** outthreads;

int final_line_written = 0; // Whether or not the fianl line is written
#define FILE_MAP_START 0
long long int  BUFFSIZE = THREAD_COUNT * BLOCK_SIZE;
// mutex mtx;

/*
    XOR's two objects begaining at s1's off for n.
    And beginging at s2's 0 for n.

*/

template < typename NU >
void set_xor(NU* s1, NU* s2, std::ofstream s3, unsigned int n, unsigned int off) {
    for (unsigned int i = 0; i < n; i++) {
        s3 << s1[i + off] ^ s2[i];
    }
}

/*
    Given nonce is already set, one_block takes the thrd number and the block count and
    modifies nex[thrd] for the next block of chacha20.

    This doesn't track whether or not the count is increamented; thus, to ensure security
    please increament the count before passing it into one_block

*/

void Cc20::one_block(int thrd, uint32_t count) {
    cy[thrd][12] = count;
    memcpy(folow[thrd], cy[thrd], sizeof(uint32_t) * 16);
    #ifdef ROUNDCOUNTTWLV
    for (unsigned int i = 0; i < 6; i++) tworounds(folow[thrd]); // 8 rounds
    #else
    for (unsigned int i = 0; i < 10; i++) tworounds(folow[thrd]); // 20 rounds
    #endif
    set_conc(cy[thrd], folow[thrd], 16);
    endicha(this->nex[thrd], folow[thrd]);
}

/*
    Reads from line writes to linew, encryptes the same as rd_file_encr().

*/

void Cc20::encr(uint8_t* line, uint8_t* linew, unsigned long long int fsize) {

    unsigned long long int n = fsize;

    long long int tn = 0;
    uint32_t count = 0;
    for (long long int i = 0; i < THREAD_COUNT; i++) {
        writing_track[i] = 0;
    }
    long long int tracker = 0;
    long long int np = 0, tmpn = np % THREAD_COUNT;
    set_thread_arg(np % THREAD_COUNT, (long long int)linew, tracker, n, 0, line, count, this);
    threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, tmpn);
    np++;

    for (unsigned long long int k = 0; k < ((unsigned long long int)(fsize / 64) + 1); k++) { // If leak, try add -1

        if (n >= 64) {
            tracker += 64;
            if (tn % (BLOCK_SIZE) == 0 && (k != 0)) {
                if (threads[np % THREAD_COUNT].joinable()) {
                    #ifdef VERBOSE
                    cout << "[main] Possible join, waiting " << np % THREAD_COUNT << endl;
                    #endif
                    threads[np % THREAD_COUNT].join();
                }
                set_thread_arg(np % THREAD_COUNT, (long long int)linew + tn, tracker, n, tn, line + tn, count + 1, this);
                threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);

                tracker = 0;
                np++;
            }
        }
        else {
            if (threads[np % THREAD_COUNT].joinable() && final_line_written != 1) {
                #ifdef VERBOSE
                cout << "[main] Last Possible join, waiting " << np % THREAD_COUNT << endl;
                #endif
                threads[np % THREAD_COUNT].join();
            }
            set_thread_arg(np % THREAD_COUNT, (long long int)linew + tn, tracker, n, tn, line + tn, count + 1, this);
            threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);
        }
        count += 1;
        n -= 64;
        tn += 64;
    }
    #ifdef VERBOSE
    cout << "[main] Finished dispatching joining" << endl;
    #endif

    for (int i = 0; i < THREAD_COUNT; i++) {
        // cout<<"Trying"<<endl;
        if (threads[i].joinable()) {

            // cout << "[main] thread joining "<< i << endl;
            threads[i].join();

        }
    }
    if(ENABLE_SHA3_OUTPUT)
    {
        #ifndef DE
        hashing.add(line, fsize);
        #else 
        hashing.add(linew, fsize);
        #endif // DE
    }

}   

/*
    Creates one thread for writing and THREAD_COUNT threads for calculating the
    cypher text. It also handles disk mapping for reading, and opens oufile for
    writing. After, it will dispatch threads when there are vacancy in threads[].
    Returns when all plain is read, and all threads are joined.

*/

void Cc20::rd_file_encr(const std::string file_name, string oufile_name) {
    std::vector < uint8_t > content;
    unsigned long long int n = 0;

    struct stat sb;
    long long int fd;
    uint8_t* data;
    uint8_t* line;

    TCHAR* lpcTheFile = new TCHAR[file_name.size() + 1]; // the file to be manipulated
    lpcTheFile[file_name.size()] = 0;
    std::copy(file_name.begin(), file_name.end(), lpcTheFile);


    HANDLE hMapFile;      // handle for the file's memory-mapped region
    HANDLE hFile;         // the file handle
    BOOL bFlag;           // a result holder
    DWORD dBytesWritten;  // number of bytes written
    DWORD dwFileSize;     // temporary storage for file sizes
    DWORD dwFileMapSize;  // size of the file mapping
    DWORD dwMapViewSize;  // the size of the view
    DWORD dwFileMapStart=0; // where to start the file map view
    DWORD dwSysGran;      // system allocation granularity
    SYSTEM_INFO SysInfo;  // system information; used to get granularity
    LPVOID lpMapAddress;  // pointer to the base address of the
                          // memory-mapped region

    int iViewDelta;       // the offset into the view where the data
                      //shows up

    hFile = CreateFile(lpcTheFile,
         GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        _tprintf(TEXT("Target file is %s\n"),
            lpcTheFile);
        return;
    }

    GetSystemInfo(&SysInfo);
    dwSysGran = SysInfo.dwAllocationGranularity;

    BUFFSIZE = GetFileSize(hFile, NULL);



    // Calculate the size of the file mapping view.
    dwMapViewSize = (FILE_MAP_START % dwSysGran) + BUFFSIZE;


    // How large will the file mapping object be?
    dwFileMapSize = FILE_MAP_START + BUFFSIZE;


    // The data of interest isn't at the beginning of the
    // view, so determine how far into the view to set the pointer.
    iViewDelta = FILE_MAP_START - dwFileMapStart;

    hMapFile = CreateFileMapping(hFile,          // current file handle
        NULL,           // default security
        PAGE_READONLY, // read/write permission
        0,              // size of mapping object, high
        dwFileMapSize,  // size of mapping object, low
        NULL);          // name of mapping object
    if (hMapFile == NULL)
    {
        _tprintf(TEXT("hMapFile is NULL: last error: %d\n"), GetLastError());
        return;
    }

    lpMapAddress = MapViewOfFile(hMapFile,            // handle to
                                                  // mapping object
        FILE_MAP_READ, // read/write
        0,                   // high-order 32
                             // bits of file
                             // offset
        dwFileMapStart,      // low-order 32
                             // bits of file
                             // offset
        dwMapViewSize);      // number of bytes
                             // to map

    if (lpMapAddress == NULL)
    {
        _tprintf(TEXT("lpMapAddress is NULL: last error: %d\n"), GetLastError());
        return;
    }

    data = (uint8_t*)lpMapAddress;

    n = GetFileSize(hFile, NULL);

    line = data;
    linew = new char[n];
    _tprintf(TEXT("Able to create buffer of size %lld\n"),n);
    long long int tn = 0;
    unsigned long long int ttn = n;
    uint32_t count = 0;
    for (long long int i = 0; i < THREAD_COUNT; i++) {
        writing_track[i] = 0;
    }
    long long int tracker = 0;
    long long int np = 0, tmpn = np % THREAD_COUNT;

    #ifdef DE
    ttn -= 12;
    line = line + 12;
    #endif
    for (unsigned int i = 0; i < THREAD_COUNT; i++) {
        progress_bar[i] = 0;
    }

    thread progress = thread(display_progress, ttn);
    _tprintf(TEXT("View 2 #%d#\n"), n);


    set_thread_arg(np % THREAD_COUNT, (long long int)linew, tracker, n, 0, line, count, this);
    threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, tmpn);
    np++;

    for (unsigned long long int k = 0; k < ((unsigned long long int)(ttn / 64) + 1); k++) { // If leak, try add -1

        if (n >= 64) {
            tracker += 64;
            if (tn % (BLOCK_SIZE) == 0 && (k != 0)) {
                if (threads[np % THREAD_COUNT].joinable()) {
                    #ifdef VERBOSE
                    cout << "[main] Possible join, waiting " << np % THREAD_COUNT << endl;
                    #endif
                    threads[np % THREAD_COUNT].join();
                }
                set_thread_arg(np % THREAD_COUNT, (long long int)linew + tn, tracker, n, tn, line + tn, count + 1, this);
                threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);

                tracker = 0;
                np++;
            }
        }
        else {
            if (threads[np % THREAD_COUNT].joinable() && final_line_written != 1) {
                #ifdef VERBOSE
                cout << "[main] Last Possible join, waiting " << np % THREAD_COUNT << endl;
                #endif
                threads[np % THREAD_COUNT].join();
            }
            set_thread_arg(np % THREAD_COUNT, (long long int)linew + tn, tracker, n, tn, line + tn, count + 1, this);
            threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);
        }
        count += 1;
        n -= 64;
        tn += 64;
    }
    #ifdef VERBOSE
    cout << "[main] Finished dispatching joining" << endl;
    #endif

    for (int i = 0; i < THREAD_COUNT; i++) {
        // cout<<"Trying"<<endl;
        if (threads[i].joinable()) {

            // cout << "[main] thread joining "<< i << endl;
            threads[i].join();

        }
    }
    if(ENABLE_SHA3_OUTPUT)
    {
        #ifndef DE
        hashing.add(line, ttn);
        #else 
        hashing.add(linew, ttn);
        #endif // DE
    }
    errno_t err;
    FILE* oufile;
    err = fopen_s(&oufile,oufile_name.data(), "wb");
    if (err == 0)
    {
        printf("The file 'crt_fopen_s.c' was opened\n");
    }
    else
    {
        printf("The file 'crt_fopen_s.c' was not opened\n");
   }
    err = fclose(oufile);
    if (err == 0)
    {
        printf("The file 'crt_fopen_s.c' was closed\n");
    }
    else
    {
        printf("The file 'crt_fopen_s.c' was not closed\n");
    }
    err = fopen_s(&oufile,oufile_name.data(), "ab");
    if (err == 0)
    {
        printf("The file 'crt_fopen_s.c' was opened\n");
    }
    else
    {
        printf("The file 'crt_fopen_s.c' was not opened\n");
    }
    #ifndef DE
    // cout<<"nonce_orig: "<<this->nonce_orig <<endl;
    fwrite(this->nonce_orig, sizeof(char), 12, oufile);

    #else

    #endif
    fwrite(linew, sizeof(char), ttn, oufile);
    err = fclose(oufile);
    if (err == 0)
    {
        printf("The file 'crt_fopen_s.c' was closed\n");
    }
    else
    {
        printf("The file 'crt_fopen_s.c' was not closed\n");
    }
    #ifdef VERBOSE
    cout << "[main] Writing thread joined" << endl;
    #endif
    if (oufile_name == "a") {
        for (unsigned int i = 0; i < ttn / BLOCK_SIZE + 1; i++) {
            delete[] outthreads[i];
        }
        delete[] outthreads;
    }
    delete[] linew;
    if (progress.joinable())
        progress.join();

}

/**
 * Displays progress
 *
 * */
void display_progress(unsigned int n) {
    unsigned int current = 0;
    unsigned int acum = 0;
    unsigned int res = 50;
    cout << endl;
    while (current < res) {
        acum = 0;
        if (((float)accumulate(progress_bar, progress_bar + THREAD_COUNT, acum) / n) * res >= current) {
            current++;
            cout << "-" << flush;
        }
        Sleep(10);
    }
    cout << "100%" << endl;
}

/*
    Sets arguments in arg_track for threads.

*/

void set_thread_arg(int thrd, long long int linew1, long long int tracker, long long int n, long long int tn, uint8_t* line, uint32_t count, Cc20* ptr) {
    arg_track[thrd][0] = thrd;
    arg_track[thrd][1] = linew1;
    arg_track[thrd][2] = tracker;
    arg_track[thrd][3] = n;

    arg_line[thrd] = line;
    arg_count[thrd] = count;
    arg_ptr[thrd] = ptr;
}

void multi_enc_pthrd(int thrd) {
    uint8_t* linew1 = (uint8_t*)arg_track[thrd][1]; // Set but not used
    long long int tracker = 0; // Used
    long long int n = arg_track[thrd][3]; // Used 
    uint8_t* line = arg_line[thrd]; // Used
    uint32_t count = arg_count[thrd]; // Used 
    Cc20* ptr = arg_ptr[thrd];

    #ifdef VERBOSE
    cout << "[calc] " << thrd << " locks, starting write " << endl;
    #endif
    for (unsigned long long int k = 0; k < BLOCK_SIZE / 64; k++) {
        ptr->one_block((int)thrd, (int)count);
        #ifdef VERBOSE
        cout << "[calc] " << thrd << " had iteration, current size " << n << endl;
        #endif
        if (n >= 64) {
            for (long long int i = 0; i < 64; i++) {
                linew1[i + tracker] = (char)(line[i + tracker] ^ ptr->nex[thrd][i]);
            }

            tracker += 64;

            
            if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
                
                writing_track[thrd] = tracker;
                tracker = 0;
                #ifdef VERBOSE
                cout << "[calc] " << thrd << " returning lock, calling write, size " << writing_track[thrd] << endl;
                #endif
            }
        }
        else {
            for (int i = 0; i < n; i++) {
                linew1[i + tracker] = (char)(line[i + tracker] ^ ptr->nex[thrd][i]);
            }
            tracker += n;
            writing_track[thrd] = tracker; // Notifies the writing tread when data can be read

            #ifdef VERBOSE
            cout << "[calc] " << thrd << " on last lock, size " << writing_track[thrd] << endl;
            #endif
            break;
        }
        count += 1;
        n -= 64;
        progress_bar[thrd] += 64;
    }
    #ifdef VERBOSE
    cout << "[calc] " << thrd << " unlocks " << endl;
    #endif
}


void Cc20::set_vals(uint8_t* nonce, uint8_t* key) {
    this->nonce = nonce;
    copy(nonce, nonce + 12, this->nonce_orig);
    this->count = 0;
    for (unsigned int i = 0; i < THREAD_COUNT; i++) {
        this->cy[i][0] = 0x61707865;
        this->cy[i][1] = 0x3320646e;
        this->cy[i][2] = 0x79622d32;
        this->cy[i][3] = 0x6b206574;
        expan(this->cy[i], 13, this->nonce, 3);
        expan(this->cy[i], 4, key, 8);
    }
}

void Cc20::endicha(uint8_t* a, uint32_t* b) {
    for (unsigned int i = 0; i < 16; i++) {
        U32T8_S(a + 4 * i, b[i]);

    }
}

/**
 * Init encryption.
 *
 * This version of pdm-crypt interfaces within memory, which means
 * entire file will be read before the encryption.
 * Thus, this version is not recommended for large files (more than half
 * of your computer's memory).
 * For a memory effecient version, please use a history version (that version
 * uses at most ~320 mb for an arbitrary-size file).
 *
 * @param infile_name input file name
 * @param oufile_name output file name
 * @param nonce the nonce of this encryption
 *
 * */
void cmd_enc(string infile_name, string oufile_name, string text_nonce) {
    // cout<<infile_name<<","<<oufile_name<<","<<text_nonce<<"\n"<<endl;
    Cc20 cry_obj;
    string text_key;
    Bytes key;
    Bytes nonce;



    #ifdef WINDOWS
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    cout << "Password of the file： " << endl;
    std::getline(std::cin, text_key);
    #endif


    SHA3 key_hash;
    key_hash.add(stob(text_key).data(), text_key.size());
    key_hash.add(stob(text_key).data(), text_key.size());

    #ifdef DE
    uint8_t* line1[13] = { 0 };
    string infile_name_copy = infile_name + ".pdm";
    FILE* infile = fopen(infile_name_copy.data(), "rb");
    fread(line1, sizeof(char), 12, infile);
    if (line1 != NULL)
        text_nonce = (char*)line1;
    fclose(infile);

    #endif

    if (text_nonce.size() != 0) {
        text_nonce = pad_to_key((string)text_nonce, 12);
    }

    // Timer
    auto start = std::chrono::high_resolution_clock::now();
    // cout<<"before: "<<text_nonce.data()<<endl;
    cry_obj.set_vals((uint8_t*)text_nonce.data(), (uint8_t*)key_hash.getHash().data());


    #ifdef DE
    cry_obj.rd_file_encr(infile_name_copy, "dec-" + infile_name);
    if (ENABLE_SHA3_OUTPUT) cout << "SHA3: \"" << hashing.getHash() << "\"" << endl;

    #else
    cry_obj.rd_file_encr(infile_name, infile_name + ".pdm");
    if (ENABLE_SHA3_OUTPUT) cout << "SHA3: \"" << hashing.getHash() << "\"" << endl;
    #endif //END DE
    auto end = std::chrono::high_resolution_clock::now();
    auto dur = end - start;
    auto i_millis = std::chrono::duration_cast <std::chrono::milliseconds> (dur);
    auto f_secs = std::chrono::duration_cast <std::chrono::duration < float >> (dur);
    std::cout << f_secs.count() << '\n';
}

string convertToString(char* a, int size)
{
    int i;
    string s = "";
    for (i = 0; i < size; i++) {
        s = s + a[i];
    }
    return s;
}

int rd_inp(unsigned int argc, char** argv, string* infile) {
    int arg_c = 1;
    for (unsigned int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (argv[i][1] == 's') {
                ENABLE_SHA3_OUTPUT = 0;
            }
        }
        else {
            if (infile->empty()) {
                arg_c++;
                *infile = argv[i];
            }
            else
                return 0;
        }
    }
    if (!ENABLE_SHA3_OUTPUT)
        cout << "sha3 output disabled" << endl;
    return arg_c;
}


int main_c(int argc, char** argv) {
    std::string infile, oufile, nonce;
    if (rd_inp(argc,argv,&infile) != 2) {
        std::cout << argc << " Wrong input; Should have 1 input!\n" << std::endl;
        return 0;
    }
    Bytes cur;
    init_byte_rand_cc20(cur, 12);
    nonce = "1";
    cmd_enc(infile, "", btos(cur));
    return 0;
}

