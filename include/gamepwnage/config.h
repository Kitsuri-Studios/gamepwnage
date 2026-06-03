/**
 Gamepwnage -- Cross Platform Game Hacking API(s)

 Copyright (c) 2024-2025 bitware. All rights reserved.
 Copyright (c) 2026-ONWARDS Kitsuri Studio. All rights reserved.

 "Gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
https://github.com/Kitsuri-Studios/gamepwnage
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
#else
    #define GPWN_BKND static
#endif

#ifdef EXPORT_SYM
    // #define VISIBILITY_FLAG "default"
    #define GPWNAPI __attribute__((visibility("default")))
#else
    // #define VISIBILITY_FLAG "hidden"
    #define GPWNAPI __attribute__((visibility("hidden")))
#endif

#endif
