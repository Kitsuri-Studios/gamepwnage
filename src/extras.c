/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/mman.h>
#include <libgen.h>

#include "extras.h"


int __attribute__((visibility(VISIBILITY_FLAG))) GetExePath(char *directory, char *exename)
{
/*
#ifdef __bsd__
    //exe path fetch for BSD
    size_t path_size = 4096; //default size of directory struct
    char *exepath = (char *)malloc(path_size);
    char *exepath_dup;
    int mib[4];

    // Define the MIB array for fetching the executable path
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = -1;

    // Retrieve the executable path
    if (sysctl(mib, 4, exepath, &path_size, NULL, 0) == -1) {
        //perror("sysctl");
        free(exepath);
        return 0;
    }
    exepath_dup = strdup(exepath);
    char *_directory = dirname(exepath);    //dump the directory
    char *_exename = basename(exepath_dup); //dump the exe name

    strcpy(directory, _directory);
    strcpy(exename, _exename);

    free(exepath);
    free(exepath_dup);
    /*
    char *exe_name;
    exe_name = getprogname();
    strcpy(exename, exe_name);
    */
//#else
    //exe path fetch for linux based systems
    static const uint MAX_LENGTH = 4096;
    char *exepath = (char *)malloc(MAX_LENGTH);
    char *exepath_dup;
    char *_directory;
    char *_exename;
    ssize_t len = readlink("/proc/self/exe", exepath, MAX_LENGTH - 1);
    if (len != -1)
    {
        exepath[len] = '\0';
        exepath_dup = strdup(exepath);
        if(!exepath_dup) {
            free(exepath);
            return 0;
        }
        if(directory) {
            _directory = dirname(exepath);
            strcpy(directory, _directory);
            size_t dirlen = strlen(_directory);
            directory[dirlen] = '/';
            directory[dirlen + 1] = '\0';
            dirlen++;
        }
        if(exename)
        {
            _exename = basename(exepath_dup);
            strcpy(exename, _exename);
        }
    }
    else
    {
        perror("readlink() error: can't fetch exe path");
        free(exepath);
        return 0;
    }
    free(exepath);
    free(exepath_dup);
//#endif
    return 1;
}

int __attribute__((visibility(VISIBILITY_FLAG))) GetPROTfromStr(char *permission_str)
{
    int _PROT = 0;
    for(int i=0; i < strlen(permission_str); i++) {
        if(permission_str[i] == 'r' || permission_str[i] == 'R')
        {
            _PROT |= PROT_READ;     //read permission
        }
        if(permission_str[i] == 'w' || permission_str[i] == 'W')
        {
            _PROT |= PROT_WRITE;    //write permission
        }
        if(permission_str[i] == 'x' || permission_str[i] == 'X')
        {
            _PROT |= PROT_EXEC;     //execution permission
        }
    }
    return _PROT;
}