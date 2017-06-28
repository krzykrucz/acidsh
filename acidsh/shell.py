import os
import sys
import shlex
import getpass
import socket
import signal
import subprocess
from ast import literal_eval
from six import PY2
import platform
import ptrace.debugger
import ptrace.syscall
from ptrace.func_call import FunctionCallOptions
from ptrace.debugger import ProcessSignal, NewProcessEvent, ProcessExecution, ProcessExit
from ptrace.syscall import SYSCALL_REGISTER, RETURN_VALUE_REGISTER, DIRFD_ARGUMENTS
from ptrace.syscall.posix_constants import SYSCALL_ARG_DICT
from ptrace.syscall.syscall_argument import ARGUMENT_CALLBACK
from ptrace.tools import locateProgram
from acidsh.constants import *
from acidsh.builtins import *
from ptrace.debugger.child import createChild
from acidsh.process import Process
from acidsh.snapshot import Snapshot, Snapshots
from collections import OrderedDict
from sys import _getframe
from acidsh.filters import (delete, move, change_permissions, change_owner,  # noqa
                          create_directory, create_link, create_write_file)  # noqa
from acidsh import SYSCALL_FILTERS

# Hash map to store built-in function name and reference as key and value
built_in_cmds = {}


def register_filter(syscall, filter_function, filter_scope=None):
    if filter_scope is None:
        # Source: http://stackoverflow.com/a/5071539
        caller_module = _getframe(1).f_globals["__name__"]
        filter_scope = caller_module.split(".")[-1]
    if filter_scope not in SYSCALL_FILTERS:
        SYSCALL_FILTERS[filter_scope] = {}
    SYSCALL_FILTERS[filter_scope][syscall] = filter_function


def parse_argument(argument):
    # createText() uses repr() to render the argument,
    # for which literal_eval() acts as an inverse function
    # (see http://stackoverflow.com/a/24886425)
    argument = literal_eval(argument.createText())
    if PY2 and isinstance(argument, str):
        argument = unicode(argument, sys.getfilesystemencoding())  # noqa
    return argument


def tokenize(string):
    return shlex.split(string)


def preprocess(tokens):
    processed_token = []
    for token in tokens:
        # Convert $-prefixed token to value of an environment variable
        if token.startswith('$'):
            processed_token.append(os.getenv(token[1:]))
        else:
            processed_token.append(token)
    return processed_token


def handler_kill(signum, frame):
    raise OSError("Killed!")


def debug_process(debugger, syscall_filters):
    format_options = FunctionCallOptions(
        replace_socketcall=False,
        string_max_length=4096,
    )

    processes = {}
    operations = []
    exit_code = 0
    snapshots = Snapshots()

    while True:
        if not debugger:
            # All processes have exited
            break

        # This logic is mostly based on python-ptrace's "strace" example
        try:
            syscall_event = debugger.waitSyscall()
        except ProcessSignal as event:
            event.process.syscall(event.signum)
            continue
        except NewProcessEvent as event:
            event.process.syscall()
            event.process.parent.syscall()
            continue
        except ProcessExecution as event:
            event.process.syscall()
            continue
        except ProcessExit as event:
            exit_code = event.exitcode
            continue

        process = syscall_event.process
        syscall_state = process.syscall_state

        syscall = syscall_state.event(format_options)

        if syscall and syscall_state.next_event == "exit":
            # Syscall is about to be executed (just switched from "enter" to "exit")
            # print(syscall.format())
            if syscall.name in syscall_filters:

                filter_function = syscall_filters[syscall.name]
                if process.pid not in processes:
                    processes[process.pid] = Process(process)
                arguments = [parse_argument(argument) for argument in syscall.arguments]

                name, paths, return_value = filter_function(processes[process.pid], arguments)

                if name is not None:
                    operations.append(name)
                    for path in paths:
                        snapshots.snapshot_path(path)

        process.syscall()

    return snapshots, exit_code


def execute(cmd_tokens, syscall_filters):
    with open(HISTORY_PATH, 'a') as history_file:
        history_file.write(' '.join(cmd_tokens) + os.linesep)

    if cmd_tokens:
        # Extract command name and arguments from tokens
        cmd_name = cmd_tokens[0]
        cmd_args = cmd_tokens[1:]

        DIRFD_ARGUMENTS.clear()
        SYSCALL_ARG_DICT.clear()
        ARGUMENT_CALLBACK.clear()
        # If the command is a built-in command,
        # invoke its function with arguments
        if cmd_name in built_in_cmds:
            return built_in_cmds[cmd_name](cmd_args)

        # Wait for a kill signal
        signal.signal(signal.SIGINT, handler_kill)

        try:
            # Spawn a child process
            cmd_tokens[0] = locateProgram(cmd_tokens[0])
            pid = createChild(cmd_tokens, False)
        except Exception as error:
            print("Error %s executing %s" % (error, cmd_name))
            return 1

        debugger = ptrace.debugger.PtraceDebugger()
        debugger.traceFork()
        debugger.traceExec()

        process = debugger.addProcess(pid, True)
        process.syscall()

        snapshots = None
        try:
            snapshots, exit_code = debug_process(debugger, syscall_filters)
            if exit_code != 0:
                print('Command unsuccessful - rollbacking changes')
                snapshots.rollback_all()
        except Exception as error:
            print("Error tracing process: %s." % error)
            return SHELL_STATUS_STOP
        except KeyboardInterrupt:
            print("%s terminated by keyboard interrupt." % cmd_name)
            return SHELL_STATUS_STOP
        finally:
            # Cut down all processes no matter what happens
            # to prevent them from doing any damage
            debugger.quit()
            if snapshots is not None:
                snapshots.clean()


    # Return status indicating to wait for next command in shell_loop
    return SHELL_STATUS_RUN


# Display a command prompt as `[<user>@<hostname> <dir>]$ `
def display_cmd_prompt():
    # Get user and hostname
    user = getpass.getuser()
    hostname = socket.gethostname()

    # Get base directory (last part of the curent working directory path)
    cwd = os.getcwd()
    base_dir = os.path.basename(cwd)

    # Use ~ instead if a user is at his/her home directory
    home_dir = os.path.expanduser('~')
    if cwd == home_dir:
        base_dir = '~'

    # Print out to console
    sys.stdout.write("[%s@%s %s]$ " % (user, hostname, base_dir))
    sys.stdout.flush()


def ignore_signals():
    # Ignore Ctrl-Z stop signal
    if platform.system() != "Windows":
        signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    # Ignore Ctrl-C interrupt signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def shell_loop():
    syscall_filters = {}
    for filter_scope in SYSCALL_FILTERS:
        if filter_scope in SYSCALL_FILTERS.keys():
            for syscall in SYSCALL_FILTERS[filter_scope]:
                syscall_filters[syscall] = SYSCALL_FILTERS[filter_scope][syscall]

    status = SHELL_STATUS_RUN

    while status == SHELL_STATUS_RUN:
        display_cmd_prompt()

        # Ignore Ctrl-Z and Ctrl-C signals
        ignore_signals()

        try:
            # Read command input
            cmd = sys.stdin.readline()
            # Tokenize the command input
            cmd_tokens = tokenize(cmd)
            # Preprocess special tokens
            # (e.g. convert $<env> into environment value)
            cmd_tokens = preprocess(cmd_tokens)
            # Execute the command and retrieve new status
            status = execute(cmd_tokens, syscall_filters)
        except:
            _, err, _ = sys.exc_info()
            print(err)


# Register a built-in function to built-in command hash map
def register_command(name, func):
    built_in_cmds[name] = func


# Register all built-in commands here
def init():
    register_command("cd", cd)
    register_command("exit", exit)
    register_command("export", export)
    register_command("getenv", getenv)
    register_command("history", history)


def main():
    # Init shell before starting the main loop
    init()
    shell_loop()


if __name__ == "__main__":
    main()
