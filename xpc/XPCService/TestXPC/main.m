//
//  main.m
//  TestXPC
//
//  Created by soulghost on 2020/6/11.
//  Copyright © 2020 soulghost. All rights reserved.
//

#import <Cocoa/Cocoa.h>

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
//    xpc_main(new_xpc_conn_handler);
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
    }
    return NSApplicationMain(argc, argv);
}
