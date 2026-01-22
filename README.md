![NATS](src/main/javadoc/images/large-logo.png)

# Java NKeys Library

The library allows you to create and use NKEYS in Java code.

![3.0.0](https://img.shields.io/badge/Current_Release-3.0.0-27AAE0?style=for-the-badge)
![3.0.1](https://img.shields.io/badge/Current_Snapshot-3.0.1--SNAPSHOT-27AAE0?style=for-the-badge)

[![Build Main Badge](https://github.com/nats-io/nkeys.java/actions/workflows/build-main.yml/badge.svg?event=push)](https://github.com/nats-io/nkeys.java/actions/workflows/build-main.yml)
[![Coverage Status](https://coveralls.io/repos/github/nats-io/nkeys.java/badge?branch=main)](https://coveralls.io/github/nats-io/nkeys.java?branch=main)
[![Maven JDK 21](https://img.shields.io/maven-central/v/io.nats/nkeys-java-jdk21?label=maven-central-jdk21)](https://mvnrepository.com/artifact/io.nats/nkeys-java-jdk21)
[![Maven JDK 25](https://img.shields.io/maven-central/v/io.nats/nkeys-java-jdk25?label=maven-central-jdk25)](https://mvnrepository.com/artifact/io.nats/nkeys-java-jdk25)
[![Javadoc](http://javadoc.io/badge/io.nats/nkeys-java-jdk21.svg?branch=main)](http://javadoc.io/doc/io.nats/nkeys-java-jdk21?branch=main)
[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue)](https://www.apache.org/licenses/LICENSE-2.0)

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
### JDK Version

This project uses Java 21 Language Level api, but builds with both Java 21 and Java 25, so creates two different artifacts.
Both have the same group id `io.nats`, and the same version but have different artifact names.

* The Java 21 artifact id is `nkeys-java-jdk21`
* The Java 25 artifact id is `nkeys-java-jdk25`

### Dependency Management

The NATS client is available in the Maven central repository,
and can be imported as a standard dependency in your `build.gradle` or `pom.xml` file,
The examples shown use the jdk 21 version, to the jdk 25 version just change the artifact id.

#### Gradle

```groovy
dependencies {
    implementation 'io.nats:nkeys-java-jdk21:3.0.0'
}
```

If you need the latest and greatest before Maven central updates, you can use:

```groovy
repositories {
    mavenCentral()
    maven {
        url "https://repo1.maven.org/maven2/"
    }
}
```

If you need a snapshot version, you must add the url for the snapshots and change your dependency.

```groovy
repositories {
    mavenCentral()
    maven {
        url "https://central.sonatype.com/repository/maven-snapshots"
    }
}

dependencies {
   implementation 'io.nats:nkeys-java-jdk21:3.0.1-SNAPSHOT'
}
```

#### Maven

```xml
<dependency>
    <groupId>io.nats</groupId>
    <artifactId>nkeys-java-jdk21</artifactId>
    <version>3.0.0</version>
</dependency>
```

If you need the absolute latest, before it propagates to maven central, you can use the repository:

```xml
<repositories>
    <repository>
        <id>sonatype releases</id>
        <url>https://repo1.maven.org/maven2/</url>
        <releases>
           <enabled>true</enabled>
        </releases>
    </repository>
</repositories>
```

If you need a snapshot version, you must enable snapshots and change your dependency.

```xml
<repositories>
    <repository>
        <id>sonatype snapshots</id>
        <url>https://central.sonatype.com/repository/maven-snapshots</url>
        <snapshots>
            <enabled>true</enabled>
        </snapshots>
    </repository>
</repositories>

<dependency>
    <groupId>io.nats</groupId>
    <artifactId>nkeys-java-jdk21</artifactId>
    <version>3.0.1-SNAPSHOT</version>
</dependency>
```

## License

Unless otherwise noted, the NATS source files are distributed
under the Apache Version 2.0 license found in the LICENSE file.
