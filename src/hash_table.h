#pragma once
#ifndef _HASH_TABLE_H_
#define _HASH_TABLE_H_

#include <stddef.h>
#include <stdint.h>
typedef struct hash_table_t hash_table_t;

hash_table_t* hash_table_create(int bucket_size, size_t key_len, int(*equals)(const void* key1, const void* key2), void (*destroy)(void* data));
void hash_table_destroy(hash_table_t* table);
void* hash_table_get(hash_table_t* table, void* key);
int hash_table_put(hash_table_t* table, void* key, void* data);
void* hash_table_remove(hash_table_t* table, void* key);

void (*hash_table_get_destroy(hash_table_t* table))(void* data);
void hash_table_for_each(hash_table_t* table, int (*callback)(void* key, void* value), int ret_values_size, int* ret_values);
int hash_table_count(hash_table_t* table);
#endif // _HASH_TABLE_H_