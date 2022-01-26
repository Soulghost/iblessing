//
//  main.m
//  iblessing-mac-sample
//
//  Created by soulghost on 2022/1/26.
//  Copyright © 2022 soulghost. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>

kern_return_t
bootstrap_look_up(mach_port_t  bootstrap_port,
                  char*        service_name,
                  mach_port_t* service_port);

void testXPC(void) {
    printf("[+] prepare for connect to suggestd\n");
    
    mach_port_t service_port;
    // com.apple.private.suggestions.reminders
    kern_return_t ret = bootstrap_look_up(bootstrap_port, "com.apple.suggestd.reminders", &service_port);
    printf("[+] service lookup result %s\n", mach_error_string(ret));
    static xpc_connection_t conn;
    conn = xpc_connection_create_mach_service("com.apple.suggestd.reminders", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t object) {
        printf("[*] connect result %p %s\n", object, xpc_copy_description(object));
    });
    xpc_connection_resume(conn);
    
    xpc_object_t req = xpc_dictionary_create(NULL, NULL, 0);
//    xpc_dictionary_set_uint64(req, "type", 'read');
//    xpc_dictionary_set_uint64(req, "numbytes", 1);
//    xpc_dictionary_set_uint64(req, "numpackets", 1);
//    xpc_dictionary_set_int64(req, "startingPacket", 1);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, req);
    char *reply_msg = xpc_copy_description(reply);
    printf("reply result %p, length %lu: %s\n", reply_msg, strlen(reply_msg), reply_msg);
//    __asm__ __volatile__ ("svc #0x0");
//    char *desc = xpc_copy_description(reply);
//    printf("[+] reply desc length %lu\n", strlen(desc));
//    NSLog(@"[+] reply desc %s\n", xpc_copy_description(reply));
    
//    xpc_dictionary_apply(reply, ^bool(const char *key, xpc_object_t value) {
//        if (strcmp(key, "status") == 0) {
//            int64_t val = xpc_int64_get_value(value);
//            val = CFSwapInt64(val) >> 32;
//            char *str = (char *)malloc(sizeof(int64_t) + 1);
//            memcpy(str, &val, sizeof(int64_t));
//            str[sizeof(int64_t)] = '\0';
//            printf("[+] status: %s\n", str);
//            free(str);
//        } else {
//            printf("\t[+] %s -> %s\n", key, xpc_copy_description(value));
//        }
//
//        return true;
//    });
    while (1) {
        
    }
}

int main(int argc, const char * argv[]) {
    testXPC();
    return 0;
}
