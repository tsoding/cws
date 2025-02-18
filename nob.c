#define NOB_IMPLEMENTATION
#define NOB_STRIP_PREFIX
#include "nob.h"

#define BUILD_FOLDER "build/"
#define EXAMPLES_FOLDER "examples/"
#define SRC_FOLDER "src/"

#define cc_with_cflags(cmd) cmd_append(cmd, "gcc", "-Wall", "-Wextra", "-ggdb", "-I.", "-I"SRC_FOLDER)
#define cc_output(cmd, output_path) cmd_append(cmd, "-o", output_path)
#define cc_no_link(cmd) cmd_append(cmd, "-c")
#define cc_input(cmd, ...) cmd_append(cmd, __VA_ARGS__)

int main(int argc, char **argv)
{
    NOB_GO_REBUILD_URSELF_PLUS(argc, argv, "nob.h");
    Cmd cmd = {0};
    Nob_Procs procs = {0};

    if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;

    cc_with_cflags(&cmd);
    cc_no_link(&cmd);
    cc_output(&cmd, BUILD_FOLDER"cws.o");
    cc_input(&cmd, SRC_FOLDER"cws.c");
    da_append(&procs, nob_cmd_run_async_and_reset(&cmd));

    cc_with_cflags(&cmd);
    cc_no_link(&cmd);
    cc_output(&cmd, BUILD_FOLDER"coroutine.o");
    cc_input(&cmd, SRC_FOLDER"coroutine.c");
    da_append(&procs, nob_cmd_run_async_and_reset(&cmd));

    if (!nob_procs_wait_and_reset(&procs)) return 1;

    cc_with_cflags(&cmd);
    cc_output(&cmd, BUILD_FOLDER"01_plain_echo_server");
    cc_input(&cmd, EXAMPLES_FOLDER"01_plain_echo_server.c", BUILD_FOLDER"cws.o");
    da_append(&procs, nob_cmd_run_async_and_reset(&cmd));

    cc_with_cflags(&cmd);
    cc_output(&cmd, BUILD_FOLDER"02_plain_async_echo_server");
    cc_input(&cmd, EXAMPLES_FOLDER"02_plain_async_echo_server.c", BUILD_FOLDER"cws.o", BUILD_FOLDER"coroutine.o");
    da_append(&procs, nob_cmd_run_async_and_reset(&cmd));

    if (!nob_procs_wait_and_reset(&procs)) return 1;

    return 0;
}
