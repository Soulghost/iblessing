@import Foundation;
//@import XPCSupport;
//#import <StringManipulation-Swift.h>

int main(int argc, const char *argv[])
{
//    ServiceDelegate *delegate = [ServiceDelegate new];
//    NSXPCListener *listener = [NSXPCListener serviceListener];
//    listener.delegate = delegate;
//
//    [listener resume];
    xpc_connection_t listener = xpc_connection_create_mach_service("com.soulghost.dynamic.entrypoint", NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t  _Nonnull peer) {
        xpc_connection_set_event_handler(peer, ^(xpc_object_t  _Nonnull object) {
            if (xpc_get_type(object) == XPC_TYPE_DICTIONARY) {
                xpc_connection_send_message(peer, object);
            }    
        });
        xpc_connection_resume(peer);
    });
    xpc_connection_resume(listener);
    CFRunLoopRun();
    return 0;
}
