# Project: FuncJacker

## Introduction
FuncJacker is a C language instrumentation project that allows you to hijack the execution of any function at will. It provides a simple and effective way to patch and unpatch functions, offering a pre-function and post-function hooking mechanism. This can be extremely useful for debugging, testing, performance monitoring, and many other scenarios.

## Current Support and Future Plans

Currently, FuncJacker only supports the x86-64 architecture and Linux operating system. However, we plan to extend our support to more platforms in the future. Please note that this project is still in development. We welcome any contributions, issues, and pull requests.

## Functions

`int patch(void *target_func, void *new_func, void *pre_func, void *post_func);`

This function is used to hijack a target function. It replaces the target function with a new function and allows you to specify a function to be executed before and after the new function.

`int unpatch(void* target_func);`

This function is used to restore the original function, effectively undoing the patch.

`int unpatch_all();`

This function is used to restore all patched functions to their original state.

## Usage

To use FuncJacker in your project, include the patcher.h header file and call the patch() function with the appropriate arguments to hijack a function. To restore the original function, call the unpatch() function with the target function as the argument. To restore all functions to their original state, call the unpatch_all() function.

## Example

```c
#include "patcher.h"

void target_func() {
    // Original function code
}

void new_func() {
    // New function code
}

void pre_func() {
    // Code to run before new_func
}

void post_func() {
    // Code to run after new_func
}

int main() {
    patch(target_func, new_func, pre_func, post_func);
    // target_func is now hijacked
    unpatch(target_func);
    // target_func is now restored
    return 0;
}
```

## License

FuncJacker is licensed under the MIT License. See LICENSE for more information.
