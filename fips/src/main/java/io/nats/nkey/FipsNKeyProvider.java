package io.nats.nkey;

import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.security.KeyPair;

@NullMarked
public class FipsNKeyProvider extends NKeyProvider {
    @Override
    public NKey createPair(NKeyType type, byte[] seed) throws IOException {
        return null;
    }

    @Override
    public KeyPair getKeyPair(NKey nkey) {
        return null;
    }

    @Override
    public byte[] sign(NKey nkey, byte[] input) {
        return new byte[0];
    }

    @Override
    public boolean verify(NKey nkey, byte[] input, byte[] signature) throws IOException {
        return false;
    }
}
