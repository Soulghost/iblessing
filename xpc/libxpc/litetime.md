- EVFILT_WORKLOOP (-17)
- EVFILT_MACHPORT (-8)

# kevent user -> kernel
dispatch_kq_unote_update -> _dispatch_kq_drain -> dispatch_kq_poll -> kevent_qos

# kevents
- kq_init
    - kevent_qos - event #0: filter -10(EVFILT_USER), ident 0x1, udata 0xfffffffffffffff8, flags 0x21

- dispatch_activate_VARIANT_mp
    - kevent_qos - event #0: filter -14(EVFILT_MEMORYSTATUS), ident 0x0, udata 0x4001087f0, flags 0x185

- dispatch_mach_install ?
    - kevent_qos - event #0: filter -8(EVFILT_MACHPORT), ident 0xf03, udata 0x400108950, flags 0x385

- dispatch_kq_poll
    - kevent_id  - event #0: filter -8(EVFILT_MACHPORT), ident 0xe03, udata 0x4001063d0, flags 0x385


# msg merge
- _dispatch_mach_merge_msg
    - flags = 0x185 => EV_UDATA_SPECIFIC | EV_DISPATCH | EV_ADD | EV_ENABLE
        - #define EV_ADD              0x0001      /* add event to kq (implies enable) */
        - #define EV_ENABLE           0x0004      /* enable event */
        - #define EV_DISPATCH         0x0080      /* disable event after reporting */
        - #define EV_UDATA_SPECIFIC   0x0100      /* unique kevent per udata value */

# reply routine
_dispatch_workloop_worker_thread -> _dispatch_wlh_worker_thread
    - _dispatch_event_loop_merge
        - _dispatch_kevent_mach_msg_drain -> _dispatch_kevent_mach_msg_recv -> dispatch_mach_merge_msg_VARIANT_mp
        - -> _dispatch_mach_handle_or_push_received_msg -> _dispatch_lane_push -> _dispatch_mach_wakeup ->
        - -> _dispatch_queue_wakeup -> _dispatch_queue_push_queue -> _dispatch_event_loop_poke
        - -> _dispatch_kevent_workloop_poke -> _dispatch_kq_poll

    - 



