/*
 * Copyright (C) 2023 Guillaume Pellegrino
 * This file is part of brssh <https://github.com/guillaumepellegrino/brssh>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define PROCESS_PRIVATE
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "process.h"

#define PIPE_RDEND 0
#define PIPE_WREND 1


bool process_start(process_t *process, const char *argv[]) {
    assert(process);
    assert(argv);

    int pid = -1;
    int pipe_in[2];
    int pipe_out[2];

    process->pid = 0;
    process->input = -1;
    process->output = -1;

    assert(pipe(pipe_in) == 0);
    assert(pipe(pipe_out) == 0);

    pid = fork();
    if (pid == 0) {
        // redirect stdin to pipe_in
        assert(close(0) == 0);
        assert(dup2(pipe_in[PIPE_RDEND], 0) == 0);
        assert(close(pipe_in[PIPE_WREND]) == 0);

        // redirect stdout to pipe_out
        assert(close(1) == 0);
        assert(dup2(pipe_out[PIPE_WREND], 1) == 1);
        assert(close(pipe_out[PIPE_WREND]) == 0);
        assert(close(pipe_out[PIPE_RDEND]) == 0);

        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);

        // run program
        execvp(argv[0], (char **) argv);

        // unreachable
        return false;
    }
    else if (pid < 0) {
        fprintf(stderr, "fork() failed: %m\n");
        return false;
    }


    assert(close(pipe_in[PIPE_RDEND]) == 0);
    assert(close(pipe_out[PIPE_WREND]) == 0);

    process->pid = pid;
    assert((process->input = pipe_in[PIPE_WREND]) >= 0);
    assert((process->output = pipe_out[PIPE_RDEND]) >= 0);

    return true;
}

void process_stop(process_t *process) {
    assert(process);
    if (process->pid > 0) {
        kill(process->pid, SIGKILL);
        waitpid(process->pid, NULL, 0);
    }
    if (process->input >= 0) {
        close(process->input);
    }
    if (process->output >= 0) {
        close(process->output);
    }
}

int process_get_pid(process_t *process) {
    assert(process);
    return process->pid;
}
