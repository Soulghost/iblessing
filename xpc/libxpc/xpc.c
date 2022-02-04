#if 0
xpc_connection_check_in -> dispatch_mach_connect_VARIANT_mp -> dispatch_activate_VARIANT_mp 
-> _dispatch_lane_resume(_dispatch_queue_resume_VARIANT_mp) -> dispatch_lane_resume_activate 
-> _dispatch_lane_resume(_dispatch_queue_resume_VARIANT_mp)
#endif

DISPATCH_NOINLINE
static void
_dispatch_lane_resume_activate(dispatch_lane_t dq)
{
	if (dx_vtable(dq)->dq_activate) {
		dx_vtable(dq)->dq_activate(dq); // dispatch_mach_activate_VARIANT_mp
	}

	_dispatch_lane_resume(dq, DISPATCH_ACTIVATION_DONE); // _dispatch_queue_resume_VARIANT_mp
}

/**
 *  Set Handler 
 */
void __cdecl xpc_connection_set_event_handler(xpc_connection_t connection, xpc_handler_t handler) {
	if (xpc_get_type(connection) != _OBJC_CLASS_$_OS_xpc_connection) {
		__xpc_api_misuse();
	}

	// NOTICE: exclusive load / store
	xpc_handler_t handler = connection->handler_0x20; 
	uint32_t flags = connection->flags;
	if (!(flags & (1 << 8))) {
		connection->handler_0x20 = handler; 
		connection->flags = 1;
		return;
	}

	connection->handler_0xA8 = handler;
	dispatch_mach_t channel = connection->channel;
	return dispatch_mach_receive_barrier_f(channel, connection, &__xpc_connection_set_event_handler2);
}

__int64 __fastcall _xpc_connection_set_event_handler2(__int64 a1)
{
  _xpc_connection_mach_event(a1, 15, 0LL);
  return _xpc_release(a1);
}

void __cdecl xpc_connection_resume(xpc_connection_t connection)
{
  unsigned int *v2; // x9
  unsigned int v3; // w8

  if ( xpc_get_type(connection) != &OBJC_CLASS___OS_xpc_connection)
    _xpc_api_misuse("Given object not of required type.");

  // NOTICE: exclusive load / store
  state = connection->mem_0x1c;
  connection->mem_0x1c = state - 1;

  if (state == 1) {
	  if ( (_xpc_connection_activate_if_needed(connection, 0LL) & 1) != 0 ) { // this way
      	return; // commonly
	  }
  } else if (state == 0) {
	  _xpc_api_misuse("Over-resume of a connection.");
  }
  dispatch_resume(*((dispatch_object_t *)connection + 18));
}

/**
 * Send Message
 */
void __cdecl __noreturn xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message)
{
  if ( connection == (xpc_connection_t)&OBJC_CLASS___OS_xpc_connection )
  {
    if ( message == &OBJC_CLASS___OS_xpc_dictionary )
      _xpc_connection_pack_message(connection, message, 0LL);
      __xpc_connection_enqueue();
    _xpc_api_misuse("Message types other than dictionaries are not supported.");
  }
  _xpc_api_misuse("Given object not of required type.");
}

void __fastcall __noreturn _xpc_connection_pack_message(ib_xpc_connection_t *connect, void *message, int a3)
{
  int reply_port; // w20
  ib_xpc_connection_t *remote_connection; // x0
  __int64 v8; // x0

  reply_port = _xpc_dictionary_extract_reply_port(message);
  remote_connection = (ib_xpc_connection_t *)xpc_dictionary_get_remote_connection(message);
  if ( remote_connection == connect || !reply_port || !remote_connection )
  {
    v8 = _xpc_serializer_create();
    if ( a3 )
      *(_DWORD *)(v8 + 152) = a3;
    _xpc_serializer_pack(v8, message, LODWORD(connect->field_B8), 0LL);
  }
  _xpc_api_misuse("Attempt to send a message expecting a reply to the wrong connection.");
}

void __cdecl xpc_connection_send_message(xpc_connection_t connection, xpc_object_t message)
{
  __int64 v3; // x0
  void *v4; // x21

  if ( connection != (xpc_connection_t)&OBJC_CLASS___OS_xpc_connection )
    _xpc_api_misuse("Given object not of required type.");
  if ( message != &OBJC_CLASS___OS_xpc_dictionary )
    _xpc_api_misuse("Message types other than dictionaries are not supported.");
  packed_msg = _xpc_connection_pack_message((ib_xpc_connection_t *)connection, message, 0);
  v4 = (void *)v3;
  _xpc_connection_enqueue(connection, 0LL, packed_msg);
  xpc_release(v4);
}

__int64 __fastcall _xpc_connection_enqueue(ib_xpc_connection_t *conn, __int64 options, ib_xpc_packed_msg *packed_msg)
{
  mach_msg_bits_t hasLocal; // w22
  dispatch_mach_msg_s *dispatch_mach_msg; // x21
  dispatch_mach_s *dispatch_mach_channel; // x0
  __int64 result; // x0
  int send_error; // [xsp+4h] [xbp-2Ch] BYREF
  __int64 send_result; // [xsp+8h] [xbp-28h] BYREF

  xpc_retain(conn);
  _xpc_retain(packed_msg);
  // 0x400108bc8: mach_msg_header - id = 0x10000000, bits = 0x13, size = 0x8c local = 0, remote = 0, voucher = 0
  hasLocal = _xpc_serializer_get_mach_message_header(packed_msg)->msgh_bits & 0x1F00;// MACH_MSGH_BITS_LOCAL_MASK
  if ( hasLocal )
  {
    xpc_retain(conn);
    _xpc_retain(packed_msg);
  }
  send_result = 0xAAAAAAAAAAAAAAAALL;
  send_error = 0xAAAAAAAA;
  dispatch_mach_msg = _xpc_serializer_get_dispatch_mach_msg(packed_msg);
  dispatch_mach_channel = conn->dispatch_mach_channel;
  if ( hasLocal )
    dispatch_mach_send_with_result_and_async_reply_4libxpc(
      dispatch_mach_channel,
      dispatch_mach_msg,
      options,
      0LL,                                      // send_flags
      &send_result,
      &send_error);
  else {
    // this way, send the msg id 0x10000000
    dispatch_mach_send_with_result(dispatch_mach_channel, dispatch_mach_msg, options, 0LL, &send_result, &send_error);
  }
  result = send_result;
  if ( (unsigned __int64)(send_result - 3) >= 2 )
  {
    if ( send_result == 10 )
      return result;
    if ( send_result != 5 )
      _xpc_connection_enqueue_cold_1();
    send_error = 0x10000003;
  }
  return _xpc_connection_handle_sent_event((int)conn, (dispatch_object_t)dispatch_mach_msg);
}