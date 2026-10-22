"""Imported by tests that run local servers: a longer listen backlog.

The default backlog of Python's servers is 5. On a small CI machine, with several client threads connecting at once and the server's accept
loop starved of the interpreter lock, the backlog overflows and Linux silently drops the connection attempt: the client then waits for the
retransmission (1 s, 3 s, 7 s... up to a minute) or times out, which looks like a hang in the code under test.
"""
import socketserver

socketserver.TCPServer.request_queue_size = 256
