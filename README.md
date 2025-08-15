# reto

This is an early draft of the Named Data Networking forwarder implementation.

In particular not all serialisation and deserialisation methods have been implemented and the implementation of PIT and FIB tables could be unsuitable for real-world traffic patterns.



Reto is primarily designed to be embedded into an application, but can be run as a standalone forwarder.

The key priorities are simplicity, performance, flexibility. These drove the following design decisions:
- The forwarder is single threaded and immediately sends the packets to all the relevant destinations. This allows minimising the impact on memory: many packets are processed with no allocations at all and no copies beyond getting the data from/to the actual faces.
- The faces have a very simple interface: try_recv() checks if anything is available, and send() sends the packet synchronously. There is no built-in async support. Instead, when the latency requirements are moderate the faces are be polled periodically. When lower latency is required, a higher-level object can handle non-blocking IO and ask the forwarder to check the specific face that the poller knows has something available.
- The built-in reference implementaion of Tables provides a simple "shared name tree" implementation for all of the relevant data structures. It assumes a multicast delivery strategy where each interest is forwarded to all the faces that registered the prefix. If more customisation is required it is always possible to plug in a different Tables implementation.
