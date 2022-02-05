__int64 _xpc_install_dispatch_hooks()
{
#if 0
libxpc:__const:00000009E161F9D0 __xpc_channel_hooks DCQ 3               ; DATA XREF: __xpc_install_dispatch_hooks↑o
libxpc:__const:00000009E161F9D8                 DCQ __xpc_connection_handle_event_inline
libxpc:__const:00000009E161F9E0                 DCQ __xpc_serializer_reply_queue_from_msg_context
libxpc:__const:00000009E161F9E8                 DCQ __xpc_connection_handle_async_reply
libxpc:__const:00000009E161F9F0                 DCQ __xpc_connection_wants_sigterm
libxpc:__const:00000009E161F9F8                 ALIGN 0x20
#endif
  return dispatch_mach_hooks_install_4libxpc(&_xpc_channel_hooks);
}