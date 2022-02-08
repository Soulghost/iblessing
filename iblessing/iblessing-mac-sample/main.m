//
//  main.m
//  iblessing-mac-sample
//
//  Created by soulghost on 2022/1/26.
//  Copyright © 2022 soulghost. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>
#include <sys/event.h>
#include <pthread/pthread.h>
//#include "libdispatch_defines.hpp"

struct kevent_qos_s
{
  uint64_t ident;
  int16_t filter;
  uint16_t flags;
  int32_t qos;
  uint64_t udata;
  uint32_t fflags;
  uint32_t xflags;
  int64_t data;
  uint64_t ext[4];
};

/*
 * Filter types
 */
#define EVFILT_READ             (-1)
#define EVFILT_WRITE            (-2)
#define EVFILT_AIO              (-3)    /* attached to aio requests */
#define EVFILT_VNODE            (-4)    /* attached to vnodes */
#define EVFILT_PROC             (-5)    /* attached to struct proc */
#define EVFILT_SIGNAL           (-6)    /* attached to struct proc */
#define EVFILT_TIMER            (-7)    /* timers */
#define EVFILT_MACHPORT         (-8)    /* Mach portsets */
#define EVFILT_FS               (-9)    /* Filesystem events */
#define EVFILT_USER             (-10)   /* User events */
#define EVFILT_UNUSED_11        (-11)   /* (-11) unused */
#define EVFILT_VM               (-12)   /* Virtual memory events */
#define EVFILT_SOCK             (-13)   /* Socket events */
#define EVFILT_MEMORYSTATUS     (-14)   /* Memorystatus events */
#define EVFILT_EXCEPT           (-15)   /* Exception events */
#define EVFILT_WORKLOOP         (-17)   /* Workloop events */

kern_return_t
bootstrap_look_up(mach_port_t  bootstrap_port,
                  char*        service_name,
                  mach_port_t* service_port);

void testXPC(void) {
    printf("[+] prepare for connect to suggestd\n");
    
    int a;
//    struct kevent_qos_s *q = &a;
//    struct dispatch_queue_s *qq = &a;
    
    mach_port_t service_port = 0;
    // com.apple.private.suggestions.reminders
    char *service_name = "com.soulghost.dynamic.entrypoint";
//    kern_return_t ret = bootstrap_look_up(bootstrap_port, service_name, &service_port);
//    printf("[+] service %s lookup result %s, port %d\n", service_name, mach_error_string(ret), service_port);
    static xpc_connection_t conn;
    conn = xpc_connection_create_mach_service(service_name, NULL, 0);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t object) {
        printf("[*] connect result %p %s\n", object, xpc_copy_description(object));
    });
    xpc_connection_resume(conn);
    
    xpc_object_t req = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(req, "type", 'read');
    xpc_dictionary_set_uint64(req, "numbytes", 1);
    xpc_dictionary_set_uint64(req, "numpackets", 1);
    xpc_dictionary_set_int64(req, "startingPacket", 1);
    xpc_connection_send_message(conn, req);
//    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, req);
//    char *reply_msg = xpc_copy_description(reply);
//    printf("reply result %p, length %lu: %s\n", reply_msg, strlen(reply_msg), reply_msg);
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

struct mach_msg_with_desc {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port_desc;
};

struct mach_msg_with_desc_response {
    mach_msg_header_t hdr;
    mach_msg_body_t body;
    mach_msg_port_descriptor_t port_desc;
    mach_msg_max_trailer_t trailer;
};

/* Setup workloop for mach msg rcv */
extern int kevent_id(void *id,
                     const struct kevent_qos_s *changelist, int nchanges,
                     struct kevent_qos_s *eventlist, int nevents,
                     void *data_out, size_t *data_available,
                     unsigned int flags);

extern int kevent_qos(int kq,
                      const struct kevent_qos_s *changelist, int nchanges,
                      struct kevent_qos_s *eventlist, int nevents,
                      void *data_out, size_t *data_available,
                      unsigned int flags);

int can_go = false;

void* wait2port(void *ctx) {
    mach_port_t recv_port = *(mach_port_t *)ctx;
    struct kevent_qos_s kev[] = {{
                             .ident = recv_port,
                             .filter = EVFILT_MACHPORT,
                             .flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
                             .fflags = (MACH_RCV_MSG | MACH_RCV_VOUCHER | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
            MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AV) |
            MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)),
                             .data = 1,
                             .qos = 0
                         }};
    struct kevent_qos_s event_out[] = {{}};

    
    int kq = kqueue();
    kern_return_t kr;
    
    while (1) {
        printf("[kevent] wait for port %d\n", recv_port);
        can_go = true;
        
        kr = kevent_qos(kq, kev, 1, event_out, 1, NULL, NULL, 0);
        printf("[kevent] receive msg on port %d, kr %d\n", recv_port, kr);
        break;
    }
    
    return NULL;
}

void testKevent(void) {
    mach_port_t recv_port = MACH_PORT_NULL;
    mach_port_t desc_port = MACH_PORT_NULL;
//    mach_port_t recv_port_set = MACH_PORT_NULL;
    assert(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &recv_port) == KERN_SUCCESS);
//    assert(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_PORT_SET, &recv_port_set) == KERN_SUCCESS);
    assert(mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &desc_port) == KERN_SUCCESS);
//    assert(mach_port_insert_member(mach_task_self_, recv_port, recv_port_set) == KERN_SUCCESS);
    printf("desc_port %d, recv_port %d\n", desc_port, recv_port);
    
    pthread_t thread;
    assert(pthread_create(&thread, NULL, &wait2port, &recv_port) == 0);
    while (!can_go) {};
    usleep(1000 * 500);
    
    struct mach_msg_with_desc _msg;
    struct mach_msg_with_desc *msg = &_msg;
    memset(msg, 0, sizeof(struct mach_msg_with_desc));
    msg->hdr.msgh_local_port = MACH_PORT_NULL;
    msg->hdr.msgh_remote_port = recv_port;
    msg->hdr.msgh_bits = MACH_MSGH_BITS_SET(
      MACH_MSG_TYPE_MAKE_SEND, // remote
      0,                       // local
      0,                       // voucher
      MACH_MSGH_BITS_COMPLEX); // other

    msg->body.msgh_descriptor_count = 0;

    // the first descriptor is valid:
    msg->port_desc.type = MACH_MSG_PORT_DESCRIPTOR;
    msg->port_desc.name = desc_port;
    msg->port_desc.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
    msg->hdr.msgh_size = sizeof(struct mach_msg_with_desc);
    kern_return_t kr = mach_msg_send((mach_msg_header_t *)msg);
    printf("[main] msg sent with result %d, desc %d\n", kr, msg->port_desc.name);
    if (kr != KERN_SUCCESS) {
        printf("error: 0x%x(%s)\n", kr, mach_error_string(kr));
        assert(false);
    }


//    struct mach_msg_with_desc_response _res;
//    struct mach_msg_with_desc_response *reply = &_res;
//    memset(reply, 0, sizeof(struct mach_msg_with_desc_response));
//
//    reply->hdr.msgh_local_port = recv_port_set;
//    reply->hdr.msgh_size = sizeof(struct mach_msg_with_desc_response);
//
//    kr = mach_msg_receive((mach_msg_header_t *)reply);
//    printf("[main] msg recv with result %d, desc port %d\n", kr, reply->port_desc.name);
//    if (kr != KERN_SUCCESS) {
//        printf("error: 0x%x(%s)\n", kr, mach_error_string(kr));
//        assert(false);
//    }
    pthread_join(thread, NULL);
}

void testDispatchMain(void) {
    printf("1. before call main queue\n");
    dispatch_async(dispatch_get_main_queue(), ^{
        printf("3. after call main queue\n");
    });
    printf("2. wait for main queue\n");
    CFRunLoopRun();
}

int main(int argc, const char * argv[]) {
//    testXPC();
    testDispatchMain();
//    testKevent();
    return 0;
}
