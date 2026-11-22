/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/


//TWEAKS
#ifndef GPWN_CONFIG_H_
#define GPWN_CONFIG_H_

// #define EXPORT_SYM              // Uncomment if you want api symbols to be exported
// #define GPWN_DEBUG              // Uncomment for debugging symbols/outputs

#ifdef GPWN_DEBUG
    #ifndef EXPORT_SYM
        #define EXPORT_SYM
    #endif
    #define GPWN_BKND
    #include <stdio.h>
    extern FILE *gpwn_flog;
    #define GPWN_LOG(...) fprintf((gpwn_flog) ? gpwn_flog : stderr, __VA_ARGS__)
#else
    #define GPWN_BKND static
    #define GPWN_LOG(...)
#endif

#ifdef EXPORT_SYM
    // #define VISIBILITY_FLAG "default"
    #define GPWNAPI __attribute__((visibility("default")))
#else
    // #define VISIBILITY_FLAG "hidden"
    #define GPWNAPI __attribute__((visibility("hidden")))
#endif

#endif
