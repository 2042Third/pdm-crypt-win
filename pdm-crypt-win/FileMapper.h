#pragma once
#include <windows.h>
#include <stdio.h>


class FileMapper 
{
public:
    void file_init(long long int buffs, TCHAR* lpcTheFile,int db);
    size_t get_next_size();
    int REPEAT_WRITING = 0;
    int file_view_allocator( char** data,int decry);
    int close();
    int debug_switch = 0;
    void mem_map(char**data);
    void mem_cache(char**data,int decry);

private:
    HANDLE hMapFile;      // handle for the file's memory-mapped region
    HANDLE hFile;         // the file handle
    BOOL bFlag;           // a result holder
    DWORDLONG dBytesWritten;  // number of bytes written
    DWORDLONG dwFileSize;     // temporary storage for file sizes
    DWORDLONG dwFileMapSize;  // size of the file mapping
    DWORDLONG dwMapViewSize;  // the size of the view
    DWORDLONG dwFileMapStart = 0; // VARIABLE where to start the file map view
    DWORDLONG dwSysGran;      // system allocation granularity
    SYSTEM_INFO SysInfo;  // system information; used to get granularity
    LPVOID lpMapAddress;  // pointer to the base address of the
                          // memory-mapped region

    int iViewDelta;       // the offset into the view where the data
                      //shows up
    DWORDLONG FILE_MAP_START=0;
    TCHAR szName[10] = TEXT("LARGEPAGE");
    long long int BUFFSIZE;
    long long int ORIG_SIZE;
    int NO_MAPPING = 1;
    //long long int MAXI_PAGE = 1835008000;
    long long int MAXI_PAGE = 1835008000;
    long long int MAXI_MEM = 2545957763;
    int DATA_IS_READ = 0;
    int multipler = 2600; 
    int MEM_MAP = 1;
    FILE* iFile;
    char*nomap;
    long long int mem_cache_start = 0;
    long long int mem_cache_end = 1835008000;
    //const long long int MAXI_PAGE = 247456000;//old
    //const long long int MAXI_PAGE = 183500800;



};

