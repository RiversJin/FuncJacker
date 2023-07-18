#include "hash_table.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// reference: https://github.com/jwerle/murmurhash.c/blob/master/murmurhash.c
uint32_t murmurhash (const char *key, uint32_t len, uint32_t seed) {
  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;
  uint32_t r1 = 15;
  uint32_t r2 = 13;
  uint32_t m = 5;
  uint32_t n = 0xe6546b64;
  uint32_t h = 0;
  uint32_t k = 0;
  uint8_t *d = (uint8_t *) key; // 32 bit extract from `key'
  const uint32_t *chunks = NULL;
  const uint8_t *tail = NULL; // tail - last 8 bytes
  int i = 0;
  int l = len / 4; // chunk length

  h = seed;

  chunks = (const uint32_t *) (d + l * 4); // body
  tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

  // for each 4 byte chunk of `key'
  for (i = -l; i != 0; ++i) {
    // next 4 byte chunk of `key'
    k = chunks[i];

    // encode next 4 byte chunk of `key'
    k *= c1;
    k = (k << r1) | (k >> (32 - r1));
    k *= c2;

    // append to hash
    h ^= k;
    h = (h << r2) | (h >> (32 - r2));
    h = h * m + n;
  }

  k = 0;

  // remainder
  switch (len & 3) { // `len % 4'
    case 3: k ^= (tail[2] << 16);
    case 2: k ^= (tail[1] << 8);

    case 1:
      k ^= tail[0];
      k *= c1;
      k = (k << r1) | (k >> (32 - r1));
      k *= c2;
      h ^= k;
  }

  h ^= len;

  h ^= (h >> 16);
  h *= 0x85ebca6b;
  h ^= (h >> 13);
  h *= 0xc2b2ae35;
  h ^= (h >> 16);

  return h;
}

typedef struct hash_node_t{
    void* key;
    void* value;
    struct hash_node_t* next;
} hash_node_t;

typedef struct hash_table_t{
    int bucket_size;
    int count;
    size_t key_len;
    size_t entry_count;
    int (*equals)(const void*, const void*);
    void (*destroy)(void*);
    hash_node_t* buckets[0];
} hash_table_t;

hash_table_t* hash_table_create(int bucket_size, size_t key_len, int (*equals)(const void*, const void*), void (*destroy)(void*)){
    int struct_size = sizeof(hash_table_t) + sizeof(hash_node_t*) * bucket_size;
    hash_table_t* table = malloc(struct_size);
    if(table == NULL){
        return NULL;
    }
    memset(table, 0, struct_size);
    table->bucket_size = bucket_size;
    table->key_len = key_len;
    table->equals = equals;
    table->destroy = destroy;
    return table;
}

void hash_table_destroy(hash_table_t* table){
    if(table == NULL){
        return;
    }
    for(int i = 0; i < table->bucket_size; i++){
        hash_node_t* node = table->buckets[i];
        while(node != NULL){
            hash_node_t* next = node->next;
            free(node);
            node = next;
        }
    }
    free(table);
}

void* hash_table_get(hash_table_t* table, void* key){
    if(table == NULL || key == NULL){
        return NULL;
    }
    uint32_t hash_code = murmurhash(key, table->key_len, 0);
    int index = hash_code % table->bucket_size;
    hash_node_t* node = table->buckets[index];
    while(node != NULL){
        if(table->equals(node->key, key)){
            return node->value;
        }
        node = node->next;
    }
    return NULL;
}

int hash_table_put(hash_table_t* table, void* key, void* value){
    if(table == NULL || key == NULL){
        return -1;
    }
    uint32_t hash_code = murmurhash(key, table->key_len, 0);
    int index = hash_code % table->bucket_size;
    hash_node_t* node = table->buckets[index];
    while(node != NULL){
        if(table->equals(node->key, key)){
            if(table->destroy != NULL){
                table->destroy(node->value);
            } else {
                free(node->value);
            }
            node->value = value;
            return 0;
        }
        node = node->next;
    }
    node = malloc(sizeof(hash_node_t));
    if(node == NULL){
        return -1;
    }
    node->key = key;
    node->value = value;
    node->next = table->buckets[index];
    table->buckets[index] = node;
    table->count++;
    return 0;
}

void* hash_table_remove(hash_table_t* table, void* key){
    if(table == NULL || key == NULL){
        return NULL;
    }
    uint32_t hash_code = murmurhash(key, table->key_len, 0);
    int index = hash_code % table->bucket_size;
    hash_node_t* node = table->buckets[index];
    hash_node_t* prev = NULL;
    while(node != NULL){
        if(table->equals(node->key, key)){
            if(prev == NULL){
                table->buckets[index] = node->next;
            } else {
                prev->next = node->next;
            }
            void* value = node->value;
            free(node->key);
            free(node);
            table->count--;
            return value;
        }
        prev = node;
        node = node->next;
    }
    return NULL;
}

int hash_table_count(hash_table_t* table){
    if(table == NULL){
        return 0;
    }
    return table->count;
}

void (*hash_table_get_destroy(hash_table_t* table))(void* data){
    if(table == NULL){
        return NULL;
    }
    return table->destroy;
}

void hash_table_for_each(hash_table_t* table, int (*callback)(void* key, void* value), int ret_values_size, int* ret_values){
    if(table == NULL || callback == NULL){
        return;
    }
    for(int i = 0; i < table->bucket_size; i++){
        hash_node_t* node = table->buckets[i];
        while(node != NULL){
            int ret = callback(node->key, node->value);
            if(ret_values != NULL && i < ret_values_size){
                ret_values[i] = ret;
            }
            node = node->next;
        }
    }
}