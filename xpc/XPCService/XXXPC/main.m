//
//  main.m
//  XXXPC
//
//  Created by soulghost on 2020/6/11.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

static void new_xpc_conn_handler(xpc_connection_t peer) {
    xpc_connection_set_event_handler(peer, ^(xpc_object_t  _Nonnull object) {
        if (xpc_get_type(object) == XPC_TYPE_DICTIONARY) {
            NSLog(@"[+] got xpc message");
            xpc_connection_t remote = xpc_dictionary_get_remote_connection(object);
            xpc_object_t reply = xpc_dictionary_create_reply(object);
            xpc_dictionary_set_bool(reply, "reply", true);
            xpc_connection_send_message(remote, reply);
            NSLog(@"[+] reply sent");
        } else {
            NSLog(@"[-] error message received");
        }
    });
    xpc_connection_resume(peer);
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        // insert code here...
        NSLog(@"Hello, World!");
        xpc_connection_t c = xpc_connection_create("com.soulghost.TestXPC", NULL);
        xpc_connection_set_event_handler(c, ^(xpc_object_t  _Nonnull object) {
            
        });
        xpc_connection_resume(c);
        
        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
        xpc_connection_send_message(c, msg);
//        xpc_dictionary_t msg = xpc_dictionary_create(NULL, NULL, 0);
    }
    return 0;
}
