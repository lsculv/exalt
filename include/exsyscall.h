#ifndef EXALT_EXSYSCALL_H
#define EXALT_EXSYSCALL_H

#include "exint.h"

u64 sys_write(unsigned int fd, const char* buf, usize count);

#endif // ifndef EXALT_EXSYSCALL_H
