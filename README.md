# Bench
Chat protocols such as XMPP, though sound in principle, are bound by a number of problems. One of them is the necessity for servers make it a *federated*, rather than a *distributed* system. One can, of course, maintain their own server, but that requires a fair amount of effort.

Another difficulty of XMPP is the relatively burdensome XML encoding. Though the XML protocol has its merits, it more often than not causes the size of the transmission to be significantly greater than that of the message itself.

Bencode is a similar scheme of encoding messages and data structures to a comprehensible, standard stream of bytes, but it adds less encoding overhead than XML.

Another benefit of bencode is that it has no special bias toward ASCII payloads. It is able to handle any binary content. Thus, transmitting and storing encrypted bytes inside of other structures requires no special consideration.

**Bench**, short for *bencoded chat* is a true, stateless Peer-to-Peer chat protocol, which makes use of bencode to format its messages, and which uses CAST5 to encrypt their content, discarding keys after chats have been finished.

## The Protocol
Bench is intended to be a protocol implementable in any language. It should be notable for its simplicity and speed, and respectable for its unintrusive security. The stages of a single chat session are as follows.

-------
A Session is the structure which encapsulates a single chat session with a single peer. It maintains the address (or domain) of the target, an ID, a history of encrypted messages, and the key.

The two sides of a chat must establish a Session before exchanging messages. To do this, the initiating client, called C1, sends a bencoded octet stream to the recieving client, called C2. This octet stream contains the following, in no particular order:

* `v` Version number (i.e. `1.0`)
* `t` A string `NEW SESSION`
* C1's RSA public key, decomposed into:
    * `m` Prime modulus (string)
    * `e` Exponent (not human readable, currently)

*(Note: the encoding of public keys is finnicky and subject to change, due to the bencode library used by the current implementation.)*

If C2 accepts the session, it selects 64 random bits, encrypts them to C1's RSA public key, and sends the following data, in no particular order:

* `v` Version number (i.e. `1.1`)
* `t` A string `OKAY`
* `k` The RSA encrypted 64 bits, generated by C2
* C2's RSA public key, decomposed into:
    * `m` Prime modulus (string)
    * `e` Exponent (not human readable, currently)

C1 should decrypt the 64 bits recieved, then generate 64 more. It appends these 64 bits to those generated by C2. It then encrypts the 64 newly generated bits to C2's public key, and sends them immediately, with the following data:

* `t` A string `OKAY`
* `k` The RSA encrypted 64 bits, generated by C1

C2 decrypts the C1's 64 bits with its private key, and, similarly, appends them to its 64 bits. It uses these 128 bits as its CAST5 key. C1 and C2 now share a key.

The session ID (SID) should be determined individually by appending the *receiving* client's IP address (without port) to the *initiating* client's IP address, each as known by the remote party, then using performing a SHA256 hash on the result.

Messages are always sent to port `9419`. Because Bench is a stateless protocol, the connection should be closed as soon as the message is transmitted. The actual encoding of the message is as follows:

* `sid` The SID number of the session that the message is part of
* `m` The message, indivually encrypted by CAST5 cipher, padded with null bytes
