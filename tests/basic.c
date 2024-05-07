#include <ex/sys/syscall.h>
int main(int argc, char* argv[]) {
    sys_exit_group(0);
    return 0;
}
