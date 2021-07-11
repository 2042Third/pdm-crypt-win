


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

#include "pdm_dev.hpp"
#include "FileMapper.h"

#include "sha3_wrapper.hpp"
#include "cc20_multi.h"
// #include <condition_variable>
// #include <boost/algorithm/string/trim.hpp>
#include <thread>


// For windows memory mapped read


#define _MBCS

#include <wchar.h>
#include <Tchar.h>

//#include <io.h>
//#include <fcntl.h>


//
unsigned long long int thrd2_ = 0;

using namespace std;
// using boost::thread;
#ifdef DE 
int DECRY = 1;
#else
int DECRY = 0;
#endif

int ENABLE_SHA3_OUTPUT = 1; // Enables sha3 output

void multi_enc_pthrd(int thrd);
//void set_thread_arg(int thrd, long long int np, long long int tracker, long long int n, long long int tn, uint8_t* line, uint32_t count, Cc20* ptr);

unsigned long long int LARGE_BUFF = 1048576;

int last_thread_dispatched = 0;

const int BLOCK_SIZE = 6912000;
/* Invariant: BLOCK_SIZE % 64 == 0
                                 115200, 256000, 576000, 1152000,2304000,4608000,6912000,9216000 ...
                                 Block size*/
FileMapper fmpr;
const int THREAD_COUNT = 30; // Make sure to change the header file's too.

/**
When FIRST_BACK_LOG == 1, 
    per block total size written to file is increased by 12 bytes, prepended onto the begining of the file.
    per block total size read from file is decreased by 12 bytes, readings starts at offset 12-bytes into the file.


*/
int FIRST_BACK_LOG = 1; 

uint32_t folow[THREAD_COUNT][17]; // A copy of a state.

// Statically allocates, and uses BLOCK_SIZE*THREAD_COUNT of memory. 
char thread_track[THREAD_COUNT][BLOCK_SIZE] = { {0} };
int DEBUG_SWITCH_CC20 = 0;
int progress_bar[THREAD_COUNT];
int DISPLAY_PROG = 1;

int REPEAT_WRITING = 0;

unsigned long long int writing_track[THREAD_COUNT]; // Tells the writer thread how much to read; should only be different on the last block.

char* linew;

char* arg_track_linew[THREAD_COUNT];
char* arg_track_line[THREAD_COUNT];

unsigned long long int arg_track[THREAD_COUNT][6];
/* Passes arguments into threads.
                                       arg_track[THREAD_COUNT][0] ---> Thread number
                                       arg_track[THREAD_COUNT][1] ---> NOT USED
                                       arg_track[THREAD_COUNT][2] ---> NOT USED
                                       arg_track[THREAD_COUNT][3] ---> Remaining plain size
                                       arg_track[THREAD_COUNT][4] ---> NOT USED*/



sha3_wrapper hashing; // A rolling hash of the input data.

uint8_t* arg_line[THREAD_COUNT]; // Addresses of memory mapped plain text from disk.

uint32_t arg_count[THREAD_COUNT]; // Count of each chacha 20 block

Cc20* arg_ptr[THREAD_COUNT]; // Parent pointers for each thread.

// recursive_mutex locks[THREAD_COUNT]; // All locks for threads, each waits for the writing is done on file or memory.

thread threads[THREAD_COUNT]; // Threads

char** outthreads;

int final_line_written = 0; // Whether or not the fianl line is written
#define FILE_MAP_START 0
unsigned long long int  BUFFSIZE = THREAD_COUNT * BLOCK_SIZE;
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
    Creates one thread for writing and THREAD_COUNT threads for calculating the
    cypher text. It also handles disk mapping for reading, and opens oufile for
    writing. After, it will dispatch threads when there are vacancy in threads[].
    Returns when all plain is read, and all threads are joined.

*/

void Cc20::rd_file_encr(const std::string file_name, string oufile_name) {
    unsigned long long int n = 0;

    struct _stat64 buf;
    uint8_t* data;
    uint8_t* line;

    TCHAR* lpcTheFile = new TCHAR[file_name.size() + 1]; // the file to be manipulated
    lpcTheFile[file_name.size()] = 0;
    std::copy(file_name.begin(), file_name.end(), lpcTheFile);

    _stat64(lpcTheFile,&buf);
    BUFFSIZE = buf.st_size;
    errno_t err;
    FILE* oufile;
    
    if (!REPEAT_WRITING) {
        
        err = fopen_s(&oufile, oufile_name.data(), "wb");
        if (err == 0) {}
        else {
            printf("The file 'crt_fopen_s.c' was not opened\n");
        }
        err = fclose(oufile);
        if (err == 0) {}
        else {
            printf("The file 'crt_fopen_s.c' was not closed\n");
        }
    }

    fmpr.file_init(BUFFSIZE, lpcTheFile, DEBUG_SWITCH_CC20);
    REPEAT_WRITING = fmpr.file_view_allocator((char**)&data,DECRY); 
    BUFFSIZE = fmpr.get_next_size();
    if (DEBUG_SWITCH_CC20) {
        _tprintf(TEXT("REPEAT_SWITCH: %d, BUFFSIZE:%lld\n"),REPEAT_WRITING, BUFFSIZE);

    }
    n = BUFFSIZE;
    line = data;
    linew = new char[BUFFSIZE];
    if (DEBUG_SWITCH_CC20)_tprintf(TEXT("Able to create buffer of size %lld\n"), BUFFSIZE);
    
    unsigned long long int tn = 0;
    unsigned long long int ttn = n;
    //uint32_t count = 0;
    for (unsigned long long int i = 0; i < THREAD_COUNT; i++) {
        writing_track[i] = 0;
    }
    unsigned long long int tracker = 0;
    unsigned long long int np = 0, tmpn = np % THREAD_COUNT;

    
    thread hash_thread;
    thread progress;

    if (DISPLAY_PROG ) {
        for (unsigned int i = 0; i < THREAD_COUNT; i++) {
            progress_bar[i] = 0;
        }

        progress = thread(display_progress);
    }
    #ifdef DE
    
    if (FIRST_BACK_LOG&& !REPEAT_WRITING) {
        ttn -= 12;
        n -= 12;
        BUFFSIZE -= 12;
        line = line + 12;
        //FIRST_BACK_LOG = 0;
    }
    #endif

    #ifdef VERBOSE
    printf(" [main] Before dispatching, remaining file %lld, ttn:%lld \n", n,ttn);
    #endif

    for (unsigned long long int k = 0; k < ((unsigned long long int)(ttn / 64) + 1); k++) { // If leak, try add -1
        //cout << "OUT" << endl;
        //printf("The n:%s\n",  line);
        if (n >= 64) {
            tracker += 64;
            if (tn % (BLOCK_SIZE) == 0 ) {
                //cout << "num " << count << " ok " << tn << " no " << n << endl;
                if (threads[np % THREAD_COUNT].joinable()) {
                    #ifdef VERBOSE
                    cout << "[main] Possible join, waiting " << np % THREAD_COUNT << ". total dispatched "<<np<< endl;
                    #endif
                    threads[np % THREAD_COUNT].join();
                }
                if (ENABLE_SHA3_OUTPUT)
                {
                    #ifndef DE
                    //printf("The n:%lld, %c, %c\n",n,line[tn], line[tn+1]);
                    if (n > BLOCK_SIZE)hashing.add(line + tn, BLOCK_SIZE);
                    else { 
                        //printf("The last:%lld, %c, %c\n", tn,line[tn+n-1],line[tn+n]);
                        hashing.add(line + tn, n); 
                    }
                    #else 
                    
                    #endif // DE
                }
                if (DEBUG_SWITCH_CC20)cout << count + 1 << " is the counter" << endl;
                set_thread_arg(np % THREAD_COUNT, (char*)linew + tn, tracker, n, tn, line + tn, count + 1, this);
                threads[np % THREAD_COUNT] = thread(multi_enc_pthrd, np % THREAD_COUNT);
                #ifdef VERBOSE
                printf("[main] Thread % d dispatched, offset %lld, remaining file % lld \n",(np)%THREAD_COUNT,tn,n);
                #endif
                tracker = 0;
                np++;
            }
        }

        count += 1;
        n -= 64;
        tn += 64;
    }
    #ifdef VERBOSE
    cout << "[main] Finished dispatching joining" << endl;
    #endif

    for (int i = 0; i < THREAD_COUNT; i++) {
        //cout<<"Trying----------"<<endl;
        if (threads[i].joinable()) {
            
            threads[i].join();
            #ifdef VERBOSE
            cout << "[main] thread joined " << i << endl;
            #endif
        }
    }
    #ifdef VERBOSE
    cout << "[main] Finished joining" << endl;
    #endif
    /** moved inside the threads*/
   
    
    err = fopen_s(&oufile,oufile_name.data(), "ab");
    if (err == 0)
    {
        #ifdef VERBOSE
        printf("The file 'crt_fopen_s.c' was opened\n");
        #endif
    }
    else
    {
        printf("The file 'crt_fopen_s.c' was not opened\n");
    }
    #ifndef DE
    //cout<<"nonce_orig: "<<this->nonce_orig <<endl;
    if(FIRST_BACK_LOG)fwrite(this->nonce_orig, sizeof(char), 12, oufile);
    if (DEBUG_SWITCH_CC20) printf("Writing event happened, size %lld\n", 12);
    #endif

    fwrite(linew, sizeof(char), ttn, oufile);
    if (DEBUG_SWITCH_CC20) printf("Writing event happened, size %lld\n", ttn);
    #ifdef DE
    if(ENABLE_SHA3_OUTPUT)hashing.add(linew,ttn);
    #endif
    err = fclose(oufile);
    if (err == 0)
    {
        #ifdef VERBOSE
        printf("The file 'crt_fopen_s.c' was closed\n");
        #endif
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
    if (DEBUG_SWITCH_CC20) cout << hashing.getHash() << endl;
    FIRST_BACK_LOG = 0;
    if (DISPLAY_PROG) {
        if (progress.joinable())
            progress.join();
    }
    if (!fmpr.close()) { printf("Failed to close the files.\n"); }
    if (REPEAT_WRITING) { 
        rd_file_encr(file_name, oufile_name);
    }
}




/**
 * Displays progress
 *
 * */
void display_progress() {
    
    unsigned long long int current = 0;
    unsigned long long int acum = 0;
    unsigned long long int res = 50;
    cout << endl;
    while (current < res) {
        acum = 0;
        if (((float)accumulate(progress_bar, progress_bar + THREAD_COUNT, acum) / BUFFSIZE) * res >= current) {
            current++;
            cout << "-" << flush;
        }
        Sleep(10);
    }
    if(!REPEAT_WRITING)cout << "100%" << endl;
}

/*
    Sets arguments in arg_track for threads.

*/

void set_thread_arg(int thrd, char* linew1, long long int tracker, unsigned long long int n, long long int tn, uint8_t* line, uint32_t count, Cc20* ptr) {
    arg_track[thrd][0] = thrd;
    arg_track_linew[thrd] = (char*)linew1;
    arg_track[thrd][2] = tracker;
    arg_track[thrd][3] = n;

    arg_line[thrd] = line;
    arg_count[thrd] = count;
    arg_ptr[thrd] = ptr;
}

void multi_enc_pthrd(int thrd) {
    uint8_t* linew1 = (uint8_t*)arg_track_linew[thrd]; // Set but not used
    unsigned long long int tracker = 0; // Used
    unsigned long long int n = arg_track[thrd][3]; // Used 
    uint8_t* line = arg_line[thrd]; // Used
    uint32_t count = arg_count[thrd]; // Used 
    Cc20* ptr = arg_ptr[thrd];

    if (thrd == 0)thrd2_++;
    #ifdef VERBOSE
    cout <<"[calc] " << thrd << " locks, starting write "<<n << endl;
    //printf("[calc telmtr] %d tracker:%lld n:%lld linew1 addr:%lld\n",thrd,tracker,n,(unsigned long long int)linew1);
    #endif
    for (unsigned long long int k = 0; k < BLOCK_SIZE / 64; k++) {
        ptr->one_block((int)thrd, (uint32_t)count);
        
        if (n >= 64) {
            for (unsigned int i = 0; i < 64; i++) {
                linew1[i + tracker] = (char)(line[i + tracker] ^ ptr->nex[thrd][i]);
                //linew1[i + tracker] = (char)(line[i + tracker]);// ^ ptr->nex[thrd][i]);
            }

            tracker += 64;

            #ifdef VERBOSE
            //if (thrd ==0  && thrd2_>=0 ) cout << "THREAD 2'S TRACKER " << tracker << " current tracker=" << linew1[tracker ] << " stack BLOCK_SIZE=" << BLOCK_SIZE << endl;
            #endif
            if (tracker >= (BLOCK_SIZE)) { // Notifies the writing tread when data can be read
                #ifdef VERBOSE
                cout << "[calc] " << thrd << " returning lock, calling write, size " << tracker << endl;
                #endif
                writing_track[thrd] = tracker;
                tracker = 0;
                
            }
        }
        else {
            for (int i = 0; i < n; i++) {
                linew1[i + tracker] = (char)(line[i + tracker] ^ ptr->nex[thrd][i]);
               // linew1[i + tracker] = (char)(line[i + tracker]);//^ ptr->nex[thrd][i]);
            }
            tracker += n;
            writing_track[thrd] = tracker; // Notifies the writing tread when data can be read
            last_thread_dispatched = 1;
            #ifdef VERBOSE
            cout << "[calc] " << thrd << " on last lock, size " << writing_track[thrd] << endl;
            #endif
            break;
        }
        count += 1;
        n -= 64;
        if(DISPLAY_PROG) progress_bar[thrd] += 64;
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


    hashing.close_all();
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


void set_config(char* inp) {
    string a = inp;
    for (unsigned int i = 0; i < a.size(); i++) {
        if (a[i] == 's') ENABLE_SHA3_OUTPUT = 0;
        else if (a[i] == 'h') DISPLAY_PROG = 0;
        else if (a[i] == 'D') DEBUG_SWITCH_CC20=1;
    }
}

int rd_inp(unsigned int argc, char** argv, string* infile) {
    int arg_c = 1;
    for (unsigned int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            set_config(argv[i]);
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

