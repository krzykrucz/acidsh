
from sys import _getframe
from collections import OrderedDict

# Use of an ordered dictionary ensures that plugin-defined filters
# (which are registered after built-in filters) are processed last
# and thus override all built-in filters hooking the same syscall
SYSCALL_FILTERS = OrderedDict()


def register_filter(syscall, filter_function, filter_scope=None):
    if filter_scope is None:
        # Source: http://stackoverflow.com/a/5071539
        caller_module = _getframe(1).f_globals["__name__"]
        filter_scope = caller_module.split(".")[-1]
    if filter_scope not in SYSCALL_FILTERS:
        SYSCALL_FILTERS[filter_scope] = {}
    SYSCALL_FILTERS[filter_scope][syscall] = filter_function
