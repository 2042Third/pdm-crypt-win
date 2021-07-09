#include "FileMapper.h"

#include "win_del.hpp"
#include <tchar.h>
#include <stdio.h>
#include <iostream>

FileMapper::FileMapper(unsigned long long int buffs, TCHAR* lpcTheFile, int db) {
    BUFFSIZE = buffs;
    debug_switch = db;
    hFile = CreateFile(lpcTheFile,
        GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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

    // Calculate the size of the file mapping view.
    dwMapViewSize = (FILE_MAP_START % dwSysGran) + BUFFSIZE;


    // How large will the file mapping object be?
    dwFileMapSize = FILE_MAP_START + BUFFSIZE;

    
    if (dwFileMapSize > MAXI_PAGE) {
        std::cout<<"Writing more than once"<<std::endl;
        dwFileMapSize = MAXI_PAGE;
        REPEAT_WRITING = 1;
    }
    
    // The data of interest isn't at the beginning of the
    // view, so determine how far into the view to set the pointer.
    iViewDelta = FILE_MAP_START - dwFileMapStart;

    hMapFile = CreateFileMapping(hFile,          // current file handle
        NULL,           // default security
        PAGE_READWRITE , // read/write permission
        dwFileMapSize << 32,              // size of mapping object, high
        dwFileMapSize,  // size of mapping object, low
        szName);          // name of mapping object
    if (hMapFile == NULL) {
        DisplayError(TEXT("CreateFileMapping"), GetLastError());
        return 0;
    }
    else
        if(debug_switch)_tprintf(TEXT("File mapping object successfully created, for start size %lld.\n"),dwFileMapStart);

    lpMapAddress = MapViewOfFile(hMapFile,            // handle to
                                                  // mapping object
        FILE_MAP_READ, // read/write
        dwFileMapStart << 32,                   // high-order 32
                             // bits of file
                             // offset
        dwFileMapStart,      // low-order 32
                             // bits of file
                             // offset
        dwFileMapSize);      // number of bytes
                             // to map
    if (REPEAT_WRITING) {
        dwFileMapStart = dwFileMapSize;
        dwFileMapSize = BUFFSIZE - dwFileMapSize;
    }
    if (debug_switch) _tprintf(TEXT("The size of the read data is %lld\n"), dwFileMapSize);

    if (lpMapAddress == NULL)
    {
        _tprintf(TEXT("lpMapAddress is NULL: last error: %d\n"), GetLastError());
        return 0;
    }

    *data = (char*)lpMapAddress;
    if (debug_switch)_tprintf(TEXT("out: %s \n"), *data);
    return REPEAT_WRITING;
}