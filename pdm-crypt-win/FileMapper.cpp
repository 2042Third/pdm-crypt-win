#include "FileMapper.h"

#include "win_del.hpp"
#include <tchar.h>
#include <stdio.h>
#include <iostream>

void FileMapper::file_init(unsigned long long int buffs, TCHAR* lpcTheFile, int db) {
    if(!REPEAT_WRITING)BUFFSIZE = buffs;
    ORIG_SIZE = buffs;
    debug_switch = db;
    hFile = CreateFile(lpcTheFile,
         GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        _tprintf(TEXT("Failure! Target file is %s\n"),
            lpcTheFile);
        return;
    }
}



size_t FileMapper::get_next_size() {
    return dwFileMapSize;
}

int FileMapper::close() {
    return UnmapViewOfFile(lpMapAddress) & CloseHandle(hMapFile) & CloseHandle(hFile);
}

int FileMapper::file_view_allocator( char** data) {
    if(debug_switch) _tprintf(TEXT("Able to reach file_view_allocator  \n"));
    GetSystemInfo(&SysInfo);
    dwSysGran = SysInfo.dwAllocationGranularity;
    MAXI_PAGE = multipler * dwSysGran;
    std::cout << "granularity: " << dwSysGran << std::endl;

    dwFileMapStart = (FILE_MAP_START / dwSysGran) * dwSysGran;

    // Calculate the size of the file mapping view.
    dwMapViewSize = (FILE_MAP_START % dwSysGran) + BUFFSIZE;


    // How large will the file mapping object be?
    dwFileMapSize = FILE_MAP_START + BUFFSIZE;

    if (debug_switch)printf("Mapping initial reading %lld\n",
        dwFileMapSize );
    
    
    
    // The data of interest isn't at the beginning of the
    // view, so determine how far into the view to set the pointer.
    iViewDelta = FILE_MAP_START - dwFileMapStart;
    hMapFile = CreateFileMapping(hFile,          // current file handle
        NULL,           // default security
        PAGE_READONLY , // read/write permission
        0,              // size of mapping object, high
        dwFileMapSize,  // size of mapping object, low
        NULL);          // name of mapping object
    if (hMapFile == NULL) {
        DisplayError(TEXT("CreateFileMapping"), GetLastError());
        return 0;
    }
    else
        if(debug_switch)_tprintf(TEXT("File mapping object successfully created, for start size %lld.\n"),dwFileMapStart);
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
        return 0;
    }
    *data = (char*)lpMapAddress+iViewDelta;//+dwFileMapStart;
    FILE_MAP_START = ORIG_SIZE- BUFFSIZE; // For next round, or doesn't matter if no next.
            
    
    //if (debug_switch)_tprintf(TEXT("out: %s \n"), *data);
    return REPEAT_WRITING;
}