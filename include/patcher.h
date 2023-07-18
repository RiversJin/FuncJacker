#pragma once
#ifndef _PATCHER_H_
#define _PATCHER_H_

int patch(void *target_func, void *new_func, void *pre_func, void *post_func);
int unpatch(void* target_func);
int unpatch_all();

#endif // _PATCHER_H_ 