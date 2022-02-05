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