![NATS](src/main/javadoc/images/large-logo.png)

# Java NKeys Library

The library allows you to create and use NKEYS in Java code.

**Current Release**: 1.5.1 &nbsp; **Current Snapshot**: 1.5.2-SNAPSHOT

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/io.nats/nkeys-java/badge.svg)](https://maven-badges.herokuapp.com/maven-central/io.nats/nkeys-java)
[![Javadoc](http://javadoc.io/badge/io.nats/nkeys-java.svg?branch=main)](http://javadoc.io/doc/io.nats/nkeys-java?branch=main)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nkeys.java/badge.svg?branch=main)](https://coveralls.io/github/nats-io/nkeys.java?branch=main)
[![Build Main Badge](https://github.com/nats-io/nkeys.java/actions/workflows/build-main.yml/badge.svg?event=push)](https://github.com/nats-io/nkeys.java/actions/workflows/build-main.yml)
[![Release Badge](https://github.com/nats-io/nkeys.java/actions/workflows/build-release.yml/badge.svg?event=release)](https://github.com/nats-io/nkeys.java/actions/workflows/build-release.yml)

# Overview

The NATS uses Ed25519 keys for identity,
authentication and authorization for entities such as Accounts, Users,
Servers and Clusters.

NKeys are based on the Ed25519 standard. This signing algorithm provides for
the use of public and private keys to sign and verify data. NKeys is designed
to formulate keys in a much friendlier fashion referencing work done in
cryptocurrencies, specifically Stellar. Bitcoin and others use a form of
Base58 (or Base58Check) to encode raw keys. Stellar utilizes a more
traditional Base32 with a CRC16 and a version or prefix byte. NKeys utilizes
a similar format with one or two prefix bytes. The base32 encoding of these
prefixes will yield friendly human-readable prefixes, e.g. 'N' = server, 'C'
= cluster, 'O' = operator, 'A' = account, and 'U' = user to help developers
and administrators quickly identify key types.

Each NKey is generated from 32 bytes. These bytes are called the seed and are
encoded, in the NKey world, into a string starting with the letter 'S', with
a second character indicating the key’s type, e.g. "SU" is a seed for a user key pair, 
"SA" is a seed for an account key pair. The seed can be used to
create the Ed25519 public/private key pair and should be protected as a private key.
It is equivalent to the private key for a PGP key pair, or the master password for your password vault.

Ed25519 uses the seed bytes to generate a key pair. The pair contains a
private key, which can be used to sign data, and a public key which can be
used to verify a signature. The public key can be distributed, and is not
considered secret.

The NKey libraries encode 32 byte public keys using Base32 and a CRC16
checksum plus a prefix based on the key type, e.g. U for a user key.

The NKey libraries have support for exporting a 64 byte private key. This
data is encoded into a string starting with the prefix ‘P’ for private. The
64 bytes in a private key consists of the 32 bytes of the seed followed by
the 32 bytes of the public key. Essentially, the private key is redundant since
you can get it back from the seed alone. The NATS team recommends storing the 32
byte seed and letting the NKey library regenerate anything else it needs for signing.

The existence of both a seed and a private key can result in confusion. It is
reasonable to simply think of Ed25519 as having a public key and a private
seed, and ignore the longer private key concept. In fact, the NKey libraries
generally expect you to create an NKey from either a public key, to use for
verification, or a seed, to use for signing.

The NATS system will utilize public NKeys for identification, the NATS system
will never store or even have access to any private keys or seeds.
Authentication will utilize a challenge-response mechanism based on a
collection of random bytes called a nonce.


## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
