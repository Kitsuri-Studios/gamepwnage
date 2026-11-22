/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#pragma once
#include "config.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// extern FILE *gpwn_flog;
GPWNAPI int gpwn_set_log_file(char *file);



#ifdef __cplusplus
}
#endif
