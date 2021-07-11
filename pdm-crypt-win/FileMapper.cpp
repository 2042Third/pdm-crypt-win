#include "FileMapper.h"
#include <io.h>
#include "win_del.hpp"
#include <tchar.h>
#include <stdio.h>
#include <iostream>

void FileMapper::file_init(    long long int buffs, TCHAR* lpcTheFile, int db) {
    if(!DATA_IS_READ)BUFFSIZE = buffs;
    ORIG_SIZE = buffs;
    debug_switch = db;
    
    if (buffs > MAXI_MEM && !DATA_IS_READ) {
    //if ( buffs > 1 && !DATA_IS_READ) {
        MEM_MAP=0;
    }
    else if(!DATA_IS_READ && MEM_MAP) {
        hFile = CreateFile(lpcTheFile,
            GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            _tprintf(TEXT("Failure! Target file is %s\n"),
                lpcTheFile);
        }
    }
    if (!MEM_MAP) fopen_s(&iFile, lpcTheFile, "rb");
}

size_t FileMapper::get_next_size() {
    if (MEM_MAP)return dwFileMapSize;
    else return mem_cache_end;
}

int FileMapper::close() {
    if(MEM_MAP)
        return UnmapViewOfFile(lpMapAddress) & CloseHandle(hMapFile) & CloseHandle(hFile);
    else
    {
        if (!REPEAT_WRITING) {
            delete[] nomap;
        }
        fclose(iFile);
        return 1;
    }
}

int FileMapper::file_view_allocator( char** data,int decry) {
    if(debug_switch) _tprintf(TEXT("Able to reach file_view_allocator  \n"));
    GetSystemInfo(&SysInfo);
    dwSysGran = SysInfo.dwAllocationGranularity;
    if(MEM_MAP)MAXI_PAGE = multipler * dwSysGran;
    if(debug_switch)std::cout << "granularity: " << dwSysGran << std::endl;

    dwFileMapStart = (FILE_MAP_START / dwSysGran) * dwSysGran;

    // Calculate the size of the file mapping view.
    dwMapViewSize = (FILE_MAP_START % dwSysGran) + BUFFSIZE;

    // How large will the file mapping object be?
    dwFileMapSize = FILE_MAP_START + BUFFSIZE;

    if (debug_switch)printf("Mapping initial reading %lld\n",
        dwFileMapSize );
    
    if (!DATA_IS_READ && decry){
        BUFFSIZE -= 12;
        mem_cache_start = 12;

    }
    if(MEM_MAP)mem_map(data);
    else {
        mem_cache(data,decry);
    }
    //if (debug_switch)_tprintf(TEXT("out: %s \n"), *data);

    DATA_IS_READ = 1;
    return REPEAT_WRITING;
}

void FileMapper::mem_cache(char** data,int decry ) {
    if (debug_switch) printf("mem_cache triggered, leaving size %lld\n",BUFFSIZE);
    if (BUFFSIZE < mem_cache_end) mem_cache_end = BUFFSIZE;
    if (_fseeki64(iFile, mem_cache_start, SEEK_SET) != 0) {
        printf("Seek failure, at %lld\n", mem_cache_start);
    }
    else if (debug_switch) {
        printf("Seek success, at offset %lld\n",mem_cache_start);
    }
    if(!DATA_IS_READ)nomap = new char[mem_cache_end];
    _flushall();
    if (fread_s((char*)nomap, mem_cache_end,sizeof(char), mem_cache_end, iFile)==NULL) {
        printf("Reading at offset %lld, for size %lld failed!\n",mem_cache_start,mem_cache_end);
    }
    else if (debug_switch) {
        printf("Read success, at offset %lld for size %lld\n", mem_cache_start, mem_cache_end);
    }
    _flushall();
    *data = nomap;
    mem_cache_start += mem_cache_end;
    if (BUFFSIZE > MAXI_PAGE) {
        REPEAT_WRITING = 1;
        mem_cache_end = (    long long int) MAXI_PAGE;
        if (debug_switch) {
            printf("REPEAT_WRITING triggered, set to 1, buff set to %lld\n",mem_cache_end);
        }
    }
    else {
        REPEAT_WRITING = 0;
        mem_cache_end = (    long long int) BUFFSIZE;

        if (debug_switch) {
            printf("REPEAT_WRITING triggered, set to 0, buff set to %lld\n", mem_cache_end);
        }
    }

    BUFFSIZE -= mem_cache_end;
}

void FileMapper::mem_map(char**data) {
    // The data of interest isn't at the beginning of the
// view, so determine how far into the view to set the pointer.
    iViewDelta = FILE_MAP_START - dwFileMapStart;
    hMapFile = CreateFileMapping(hFile,          // current file handle
        NULL,           // default security
        PAGE_READONLY, // read/write permission
        0,              // size of mapping object, high
        dwFileMapSize,  // size of mapping object, low
        NULL);          // name of mapping object
    if (hMapFile == NULL) {
        DisplayError(TEXT("CreateFileMapping"), GetLastError());
        return ;
    }
    else
        if (debug_switch)_tprintf(TEXT("File mapping object successfully created, for start size %lld.\n"), dwFileMapStart);
    lpMapAddress = MapViewOfFile(hMapFile,            // handle to
                                                  // mapping object
        FILE_MAP_READ, // read/write
        //0, 0, 0);

        0,                   // high-order 32
                             // bits of file
                             // offset
        dwFileMapStart,      // low-order 32
                             // bits of file
                             // offset
        dwFileMapSize);      // number of bytes
                             // to map

    if (debug_switch) _tprintf(TEXT("The size of the read data is %lld, starting%lld\n"), dwFileMapSize, HIWORD(dwFileMapStart));

    if (lpMapAddress == NULL)
    {
        _tprintf(TEXT("lpMapAddress is NULL: last error: %d\n"), GetLastError());
        return ;
    }
    *data = (char*)lpMapAddress + iViewDelta;//+dwFileMapStart;
    FILE_MAP_START = ORIG_SIZE - BUFFSIZE; // For next round, or doesn't matter if no next.

}