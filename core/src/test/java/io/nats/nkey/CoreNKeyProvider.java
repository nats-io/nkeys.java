package io.nats.nkey;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.jspecify.annotations.NullMarked;

import java.security.KeyPair;

import static io.nats.nkey.NKeyConstants.ED25519_PUBLIC_KEYSIZE;
import static io.nats.nkey.NKeyConstants.ED25519_SEED_SIZE;
import static io.nats.nkey.NKeyProviderUtils.encodeSeed;
import static io.nats.nkey.NKeyProviderUtils.nkeyDecode;

@NullMarked
public class CoreNKeyProvider extends NKeyProvider {

    @Override
    public NKey createNKey(NKeyType type, byte[] seed) {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(seed);
        Ed25519PublicKeyParameters publicKey = privateKey.generatePublicKey();

        byte[] pubBytes = publicKey.getEncoded();

        byte[] bytes = new byte[pubBytes.length + seed.length];
        System.arraycopy(seed, 0, bytes, 0, seed.length);
        System.arraycopy(pubBytes, 0, bytes, seed.length, pubBytes.length);

        char[] encoded = encodeSeed(type, bytes);
        return new NKey(this, type, null, encoded);
    }

    @Override
    public KeyPair getKeyPair(NKey nkey) {
        nkey.ensurePair();
        NKeyDecodedSeed decoded = nkey.getDecodedSeed();
        byte[] seedBytes = new byte[ED25519_SEED_SIZE];
        byte[] pubBytes = new byte[ED25519_PUBLIC_KEYSIZE];

        System.arraycopy(decoded.bytes, 0, seedBytes, 0, seedBytes.length);
        System.arraycopy(decoded.bytes, seedBytes.length, pubBytes, 0, pubBytes.length);

        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(seedBytes);
        Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(pubBytes);

        return new KeyPair(new CorePublicKeyWrapper(publicKey), new CorePrivateKeyWrapper(privateKey));
    }

    @Override
    public byte[] sign(NKey nkey, byte[] input) {
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(nkey.getKeyPair().getPrivate().getEncoded());
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(input, 0, input.length);
        return signer.generateSignature();
    }

    @Override
    public boolean verify(NKey nkey, byte[] input, byte[] signature) {
        Ed25519PublicKeyParameters publicKey;
        if (nkey.isPair()) {
            publicKey = new Ed25519PublicKeyParameters(nkey.getKeyPair().getPublic().getEncoded());
        }
        else {
            char[] encodedPublicKey = nkey.getPublicKey();
            byte[] decodedPublicKey = nkeyDecode(nkey.getType(), encodedPublicKey);
            publicKey = new Ed25519PublicKeyParameters(decodedPublicKey);
        }

        Ed25519Signer signer = new Ed25519Signer();
        signer.init(false, publicKey);
        signer.update(input, 0, input.length);
        return signer.verifySignature(signature);
    }
}
