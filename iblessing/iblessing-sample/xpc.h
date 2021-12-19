//
//  xpc.h
//  iokit-userland
//
//  Created by soulghost on 2021/8/13.
//

#ifndef xpc_h
#define xpc_h

#include <stdio.h>

#define XPC_CONNECTION_MACH_SERVICE_PRIVILEGED (1 << 1)

#ifdef __cplusplus
extern "C" {
#endif

typedef void* xpc_connection_t;
typedef void* xpc_object_t;
typedef void* xpc_type_t;

extern const char * const _xpc_error_key_description;
extern void* _xpc_type_error;

xpc_type_t xpc_get_type(xpc_object_t);
void xpc_connection_resume(xpc_connection_t);
void xpc_release(xpc_object_t);
xpc_connection_t xpc_connection_create_mach_service(const char*, void*, int);
void xpc_connection_set_event_handler(xpc_connection_t, void (^)(xpc_object_t object));
xpc_object_t xpc_dictionary_get_string(xpc_object_t, const char*);
char* xpc_copy_description(xpc_object_t);
void xpc_connection_send_message(xpc_connection_t, xpc_object_t);
xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message);
xpc_object_t xpc_dictionary_create(void*, void*, size_t);
void xpc_dictionary_set_uint64(xpc_object_t dictionary, const char *key, uint64_t value);
void xpc_dictionary_set_int64(xpc_object_t dictionary, const char *key, int64_t value);
void xpc_dictionary_set_data(xpc_object_t dictionary, const char *key, const void *value, size_t length);
void xpc_dictionary_set_value(xpc_object_t dictionary, const char *key, xpc_object_t value);
int xpc_dictionary_dup_fd(xpc_object_t dictionary, const char* key);
uint64_t xpc_dictionary_get_uint64(xpc_object_t dictionary, const char* key);
int64_t xpc_dictionary_get_int64(xpc_object_t dictionary, const char* key);

typedef bool (^xpc_dictionary_applier_t)(const char *key, xpc_object_t value);
void xpc_dictionary_apply(xpc_object_t xdict, xpc_dictionary_applier_t applier);

// int
xpc_object_t
xpc_int64_create(int64_t value);
int64_t
xpc_int64_get_value(xpc_object_t xint);

#ifdef __cplusplus
};
#endif

#endif /* xpc_h */
