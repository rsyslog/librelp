# RELP - The Reliable Event Logging Protocol

This is the specification for the reliable event logging protocol, called
"RELP".

Version: 0.0.1\
Date: 2008-03-19\
Author: [Rainer Gerhards](http://www.gerhards.net/rainer)

Copyright (C) 2008 by Rainer Gerhards and Adiscon GmbH. Released under the
terms of the GNU FDL.

## DESCRIPTION OF THE RELP PROTOCOL

Relp uses a client-server model with (mostly) fixed roles. The initiating part
of the connection is called the client, the listening part the server. In the
state diagrams below, C stand for client and S for server.

Relp employs a command-response model, that is the client issues commands to
which the server responds. To facilitate full-duplex communication, multiple
commands can be issued at the same time, thus multiple responses may be
outstanding at a given time. The server may reply in any order. To conserve
resources, the number of outstanding commands is limited by a window. Each
command is assigned a (relative) unique, monotonically increasing ID (called
the "transaction number" or txnr for short. Each response must include that
ID. Responses must be sent by the server in the exact same order as commands
where received.

There is one potential issue with this communications model: In it, the server
is able to respond to the client only in form or a response package. It is not
capable of issuing a command itself. During normal operations, this does not
pose any problem. However, if the server is shut down, there is no way for it
to tell the client of its shutdown intension, especially if the client does
not send any data at that moment. The same situation arises when the server
times out a session where the client has not sent any data for an extended
period of time (this probably is a good thing to conserve server resources).
Of course, an obvious answer to that need is that the server simply closes the
connection after having sent all responses (or all that it is still capable
of). The client will notice the closed connection at latest when it tries to
send new commands. However, it may be worth considering an alternate mode
where the server can issue commands to the client. One potential way to do
this would be to reserve a specific txnr (0, for example) for this use. That
txnr is only to be used by the server and only to send "out-of-band" commands.
These commands must not be acknowledged by the client, because that would
complicate the protocol more than useful for this case. So out-of-band-commands
have a "hint" status - they hint the client about something, but if they do not
arrive at the client, nothing fatal should happen. The ultimate session
closure indication would still be the tcp session close. [Please see the
"High Latency Environment" use case below for some implications this hinting
process may have].

For the time being, it has been decided that such out of band hints be not
supported.

A command and its response is called a relp transaction. A response must
always carry the same txnr as the original command.

If something goes really wrong, both the client and the server may terminate
the TCP connection at any time. Any outstanding commands are considered to
have been unsuccessful in this case.

### ERROR HANDLING

If something goes wrong (e.g. invalid framing), the peer that detects the
problem closes the underlying (TCP) connection. It may send an error/abort
hint, but MUST NOT wait for its response. The reasoning for this is that
today's Internet is not a friendly place. Trying to gracefully resolve
communications problems may lead to an attack vector. On the other hand, if
the problem was of temporary nature, it may be cleared up by the connection
reset and a new connect. So aborting errored connections is considered both
secure as well as reasonable efficient.

Note: the ability to send abort/error messages depends on the decision of
out-of-band-hint-commands (see above).

### SENDING MESSAGES

Because it is so important, I'd like to point it specifically out: sending a
message is "just" another RELP command. The reply to that command is the
ACK/NAK for the message. So every message \*is\* acknowledged. RELP options
indicate how "deep" this acknowledge is (once we have implemented that), in
the most extreme case a RELP client may ask a RELP server to ack only after
the message has been completely acted upon (e.g. successfully written to
database) - but this is far away in the future. For now, keep in mind that
message loss will always be detected because we have app-level
acknowledgement.

### RELP FRAME

All relp transaction are carried out over a consistent framing.

```text
RELP-FRAME = HEADER DATA TRAILER
DATA = [SP 1*OCTET] ; command-defined data, if DATALEN is 0, no data is present
HEADER = TXNR SP COMMAND SP DATALEN
TXNR = NUMBER ; relp transaction number, monotonically increases, starts at 1
DATALEN = NUMBER
#old:COMMAND = "open" / "syslog" / "close" / "rsp" / "abort" ; max length = 32
COMMAND = 1*32ALPHA
TRAILER = LF ; to detect framing errors and enhance human readibility
ALPHA = letter ; ('a'..'z', 'A'..'Z')
NUMBER = 1*9DIGIT
DIGIT = %d48-57
LF = %d10
SP = %d32

RSP DATA CONTENT:
RSP-HEADER = TXNR SP RSP-CODE [SP HUMANMSG] LF [CMDDATA]
RSP-CODE = 200 / 500 ; 200 is ok, all the rest currently errors
HUMANMSG = *OCTET ; a human-readable message without LF in it
CMDDATA = *OCTET ; semantics depend on original command
TXNR is as in the relp frame, it is the TXNR of the frame being responded to.
```

DATALEN is the number of octets in DATA (so the frame length excluding the
length of HEADER and TRAILER). Please note that the theoretical maximum
(999,999,999 octets) is in (almost?) all cases unsuitable for actual message
transfer. Thus, the actual maximum data length is negotiated during session
setup. In relp version 1, it is always 128K. In later versions, it shall be
operator-configurable.

TXNR 0 is reserved for hint commands. A RELP connection start with TXNR 1.
Note that TXNR montonically increases but is latched at 999,999,999. After
that TXNR, the next TXNR is 1.

### COMMAND SEMANTICS

Command can be either regular commands or hints. Regular commands are
responded to by a rsp package. They are transmitted on txnrs of 1 or above.
Hints are commands that are not being responded. They are always transmitted
with a txnr of zero. Regular commands can only be issued by the client. Hints
can be issued both by the client and the server.

#### "Command" "rsp"

This is not a real command but a response to a client-issued command. The TXNR
MUST match the client's command TXNR. The data part contains RSP-HEADER as
defined above. It is a response code, optionally followed by a space and
additional data (depending on the client's command). Return state values are:
200 - OK, 500 - error.

The ABNF for a "rsp"'s data portion is as follows:

```text
RSPDATA = STATUS SP HUMAN-TEXT [LF DATA]
STATUS = 3DIGIT
HUMAN-TEXT = *80ALPHA
DATA = 1*OCTET
```

#### Command "open"

Opens a connection to the server. Must include offers inside the data, at a
minimum the "relp_version" offer. Offers provide information about services
supported by the client.

When the server receives an open, it parses the offers, checks what it itself
supports and provides those offers that it accepts in the "rsp". The server
may send a "rsp" with an empty offer part in case it doesn't like any of the
offers. To establish a session, a "relp_version" offer MUST be included in the
response. If it is not, the client MUST close the connection.

When the client receives the "rsp", it checks the servers offers and finally
selects those that should be used during the session. Please note that this
doesn't imply the client selects e.g. security strength. To require a specific
security strength, the server must be configured to offer only those options
back to the client that it is happy to accept. So the client can only select
from those. As such, even though the client makes the final feature selection,
the server is dictating what needs to be used.

Note that the connection is only ready AFTER the client has received the
"open" response.

#### Command "close"

Closes a connection to the server. Once the client has sent a "close" command,
it must not transmit any other command over the session. When the server's rsp
answer is received, the client must close the connection.

#### Hint Command "serverclose"

This hint SHOULD be sent by the server before it closes a RELP connection. It
advised the client that the server has closed the connection. The client
SHOULD use this knowledge to close the connection on the client-side, too.
Please note that this is a hint, and as such transferred with a TXNR of 0 and
without any response from the client. Note that the client can not ask the
server to defer closing of the connection. A client MUST correctly process a
server-closed connection even if the server does not send a "serverclose"
hint. In this case, it must rely on the transport layer connection status. The
primary utility of "serverclose" is to enable the client to quickly detect a
server-closed connection, clean up resources and go into termination (or
recovery code).

#### Command "starttls"

Does the same thing as ESMTP STARTTLS: switches the connection to TLS mode.

#### Command "syslog"

This command is used to transmit a syslog message, which (in syslog message
format) is contained within the commands data portion.

### OFFERS

During session setup, "offers" are exchanged between client and server. An
"offer" describes a specific feature or operation mode. Always present must be
the "relp_version" offer which tells the other side which version of relp is in
use.

ABNF for offer strings

```text
OFFER = LF FEATURENAME ["=" VALUE *("," VALUE)]
FEATURENAME = *32OCTET
VALUE = *255OCTET

Currently defined values:
FEATURENAME VALUE
relp_version 1 (this specification)
```

#### relp_version

This offer describes the protocol version. It MUST be provided in the open
command. It has one parameter, the numerical version id. The initial version
is 1. There also exists an experimental version 0, which shall not be used in
practice.

#### commands

This offer describes which commands are supported by the remote peer. Command
that must be specified to drive the RELP protocol itself (e.g. "open", "close",
"rsp") MUST NOT be specified. Optional commands must be specified. There may be
multiple commands specified.

Sample: commands=syslog,eventlog (eventlog is a hypothetical, not yet known
command).

Please note that new commands may be specified outside of the relp
specification. Also note that if the server response does not include the
command the client is interested in, this command MUST NOT be used. The client
may then either resort to another, less featured supported command or may
terminate the relp connection.

#### relp_software

This offer describes the software (library) that is processing the relp
protocol. It is an optional offer. The idea is that when each peer knows which
software on the other peer is handling the protocol, it may be able to
work-around some known software issues. The "relp_software" has two parameters,
the first one being the name of the software as it calls itself, the second one
the version as it calls itself and the third one being an URL where information
about this software may be found. It is suggested that all three parameters are
given, but only the first one MUST actually be provided.

### STATE DIAGRAMS

... detailing some communications scenarios:

```text
Session Startup:
C S
cmd: "open", data: offer -----> (selects supported offers)
(selects offers to use) <----- cmd: "rsp", data "accepted offers"

 ... transmission channel is ready to use ....

Message Transmission
C S
cmd: "syslog", data: syslogmsg -----> (processes message)
(indicates syslog as processed) <----- cmd: "rsp", data OK/Error

Session Termination
C S
cmd: "close", data: none? -----> (processes termination request)
(terminates session) <----- cmd: "rsp", data OK/Error
 (terminates session)
```

### SECURITY CONSIDERATIONS

#### Window Size

A very large window can be abused for denial of service attacks.

#### Maximum DATALEN

A too-large DATALEN can be abused for denial of service attacks.

## Use Cases

These uses cases are not really a part of the specification. I have added them
to provide some insight into implementation specifics. These use cases may be
removed (or moved to another part of the doc set) some time in the future. In
the mean time, the serve a valuable purpose when thinking about protocol
features.

### Server Session Closure with a Hibernated Client

I define this use case in support of [rsyslog](http://www.rsyslog.com) and
other possible clients which try to reduce resource consumption.

Rsyslog utilizes highly threaded design, among others to take advantage of
multicore-machines. On the other hand, it conserves resources by only running
as many worker threads as actually needed. So if there is no traffic, it may
even be running no workers at all. The RELP client will be implemented as an
output plugin and will be executed on a worker thread. So in low-traffic cases,
the RELP client kind of hibernates, maybe even for hours (if no new message is
scheduled for transmission).

In this use case, I examine a typical scenario in a low-message volume case.
Here, the client is asked to transmit a message every now and than, at a pace
of at most one message every few seconds. It may also happen that no message is
to be sent for several minutes or even hours. Such a scenario is not as extreme
as it sounds - it may, for example, to be used for error notifications, which
hopefully happen very infrequently.

In this scenario, the client sends a command, but will usually not receive an
immediate response, because client processing is already terminated when the
server sends the response packet. Thus, the tcp stacks receive buffer buffers
the server's response until the client has another message to send. Then, the
client first checks for any outstanding responses, processes them and then
send the new message. It is expected that in this scenario, each client
invocation will process the past response and send a new packet. The response
to that packet will not be processed by the invocation that sent the command
but by the next one. So we always have one outstanding response inside the OS
buffers. Now consider the server is shutting down the connection due to
timeout or due to the fact that it needs to shutdown itself (maybe even on an
urgent case, like power failure - the point is it can not wait). On next client
invocation, the client finds an outstanding response and processes it. Then,
it tries to send a new command. That will fail, because the connection has been
terminated. The usual session recovery logic is used to re-establish the
connection when the server is back online. The command in question is
transferred after session re-establishment.

### High Latency Environment

We have a high latency environment that is otherwise quite reliable
(satellite link). We have a high traffic load. To cover this, a large
transmission window has been selected (let's say 1000 messages). Now the client
sends a burst of messages but then has nothing to do and falls asleep. Then,
the server starts sending acks. These acks are not taken off the wire by the
client (as it is inactive - rsyslog case). Eventually, the tcp window fills.
Thus the server can no longer send acks. This does not immediately pose any
problems, as the server adds the ack frames to its internal send queue.

If the client comes out of hibernation, it receives all previous sent frames,
freeing the server's tcp send window. Thus, the server can continue to send
data from its send queue (and drain it). The client, having received the
server's acks, will not stall because its own RELP window has been cleared by
the acks.

The situation is more complicated if the server intends to shut down while
the client is in hibernation. To do so, the server usually sends a
"adviseclose" command followed by a "close" command. However, neither of these
commands can be sent because the client does not take them off the wire. The
close operation is now stalled. The only option left to the server is an
unconditional termination of the session. While everything that has already
been sent to the client will be picked up by it when it comes out of
hibernation, anything left in the server's send queue will be lost in this
case. As such, acks are potentially lost. This will lead to message duplication
as the client assumes that the frames unacked at time of force-close were not
processed (there is no other safe assumption). Consequently, the client will
re-send these frames in the next session.

A cure to this situation is to have the client concurrently listen to server
requests, e.g. by running a receiver on a separate thread. The RELP protocol
does not demand this behaviour. However, it can be used to solve the above
server stall. Let's assume this is being done. Do we now have a sufficient
guarantee that the server does not stall? Under normal conditions, it is a safe
assumption that the client will be able to receive all frames sent by the
server. So a buildup of server queues should, if at all, happen only for a
short instant. However, if something goes wrong on the transmission line
(especially in high-latency cases), there may be a somewhat extended period of
time in which the server can not send acks (but only in a magnitude of a few
seconds at most). If the server intends to shutdown during such a period, a
short timeout may enable it to avoid a fore-shutdown. However, there are still
cases thinkable where a force shutdown may be required. These are deemed to be
highly unlikely.

It is the protocol implementer's choice if the slight less chance of a server
force-shutdown justifies the addition of a background thread to a program that
otherwise doesn't need one. From a protocol point of view, a force-shutdown is
a valid operation. Also, while it causes potential message duplication, it can
not cause message loss.

## Feedback and Discussion

Feedback on this document and the RELP protocol is appreciated. The
[RELP mailing list](http://lists.adiscon.net/mailman/listinfo/relp) is probably
a good place to provide it. Questions are also happily accepted.

## Copyright

Copyright (C) 2008, 2009 Rainer Gerhards and Adiscon.

Permission is granted to copy, distribute and/or modify this document under
the terms of the GNU Free Documentation License, Version 1.3 or any later
version published by the Free Software Foundation; with no Invariant Sections,
no Front-Cover Texts, and no Back-Cover Texts. A copy of the license can be
obtained from
[http://www.gnu.org/copyleft/fdl.html](http://www.gnu.org/copyleft/fdl.html)
and is also included in the [license file](gfdl.html) (if there is any
difference in those two, the one contained in the license file is the one that
this work is licensed under).
