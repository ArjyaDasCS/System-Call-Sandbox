#ifndef __system_call_handler__
#define __system_call_handler__

int waitForSystemCall(pid_t);
void signalProcessing(pid_t, char***, int,int);

#endif