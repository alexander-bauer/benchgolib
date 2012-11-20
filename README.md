# Bench
Chat protocols such as XMPP, though sound in principle, are bound by a number of problems. One of them is the necessity for servers make it a *federated*, rather than a *distributed* system. One can, of course, maintain their own server, but that requires a fair amount of effort.

Another difficulty of XMPP is the relatively burdensome XML encoding. Though the XML protocol has its merits, it more often than not causes the size of the transmission to be significantly greater than that of the message itself.

Bencode is a similar scheme of encoding messages and data structures to a comprehensible, standard stream of bytes, but it adds less encoding overhead than XML.

Another benefit of bencode is that it has no special bias toward ASCII payloads. It is able to handle any binary content. Thus, transmitting and storing encrypted bytes inside of other structures requires no special consideration.

**Bench**, short for *bencoded chat* is a true, stateless Peer-to-Peer chat protocol, which makes use of bencode to format its messages, and which uses CAST5 to encrypt their content, discarding keys after chats have been finished.

## The Protocol

Benchgo is *not* a Golang benchmark. It is a distributed (peer to peer) chat implementation using bencode to transfer messages.
