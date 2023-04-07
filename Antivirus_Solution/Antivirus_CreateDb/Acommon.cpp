#include "Acommon.h"

//convert char* to uint64_t 8bytes
uint64_t asciiToUint64(char* str)
{
    uint64_t num = 0;
    for (int i = 0; i < 8; i++) {
        num = (num << 8) | str[i];
    }
    return num;
}


