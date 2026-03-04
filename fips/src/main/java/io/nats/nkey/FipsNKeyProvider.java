package io.nats.nkey;

import org.bouncycastle.crypto.UpdateOutputStream;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.fips.FipsEdEC;
import org.bouncycastle.crypto.fips.FipsOutputSigner;
import org.bouncycastle.crypto.fips.FipsOutputVerifier;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.security.*;

import static io.nats.nkey.NKeyConstants.ED25519_PUBLIC_KEYSIZE;
import static io.nats.nkey.NKeyConstants.ED25519_SEED_SIZE;
import static io.nats.nkey.NKeyProviderUtils.encodeSeed;
import static io.nats.nkey.NKeyProviderUtils.nkeyDecode;

/**
 * Nkey Provider Implementation for FIPS
 */
@NullMarked
public class FipsNKeyProvider extends NKeyProvider {
    static {
        // Register BC-FIPS provider
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public FipsNKeyProvider() {
        try {
            setSecureRandom(SecureRandom.getInstance("DEFAULT", "BCFIPS"));
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public NKey createNKey(NKeyType type, byte[] seed) {
        byte[] pubBytes = FipsEdEC.computePublicData(FipsEdEC.Ed25519.getAlgorithm(), seed);

        byte[] bytes = new byte[pubBytes.length + seed.length];
        System.arraycopy(seed, 0, bytes, 0, seed.length);
        System.arraycopy(pubBytes, 0, bytes, seed.length, pubBytes.length);

        char[] encoded = encodeSeed(type, bytes);
        return new NKey(this, type, null, encoded);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public KeyPair getKeyPair(NKey nkey) {
        nkey.ensurePair();
        NKeyDecodedSeed decoded = nkey.getDecodedSeed();
        byte[] seedBytes = new byte[ED25519_SEED_SIZE];
        byte[] pubBytes = new byte[ED25519_PUBLIC_KEYSIZE];

        System.arraycopy(decoded.bytes, 0, seedBytes, 0, seedBytes.length);
        System.arraycopy(decoded.bytes, seedBytes.length, pubBytes, 0, pubBytes.length);

        AsymmetricEdDSAPrivateKey privateKey = new AsymmetricEdDSAPrivateKey(FipsEdEC.Ed25519.getAlgorithm(), seedBytes, pubBytes);
        AsymmetricEdDSAPublicKey publicKey = new AsymmetricEdDSAPublicKey(FipsEdEC.Ed25519.getAlgorithm(), pubBytes);

        return new KeyPair(new PublicKeyWrapper(publicKey), new PrivateKeyWrapper(privateKey));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] sign(NKey nkey, byte[] input) {
        KeyPair keyPair = nkey.getKeyPair();
        byte[] seedBytes = keyPair.getPrivate().getEncoded();
        byte[] pubBytes = keyPair.getPublic().getEncoded();
        AsymmetricEdDSAPrivateKey privateKey = new AsymmetricEdDSAPrivateKey(FipsEdEC.Ed25519.getAlgorithm(), seedBytes, pubBytes);

        FipsEdEC.EdDSAOperatorFactory factory = new FipsEdEC.EdDSAOperatorFactory();
        FipsOutputSigner<FipsEdEC.Parameters> signer = factory.createSigner(privateKey, FipsEdEC.EdDSA);

        try {
            UpdateOutputStream stream = signer.getSigningStream();
            stream.update(input, 0, input.length);
            stream.finished();
            return signer.getSignature();
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(NKey nkey, byte[] input, byte[] signature) {
        AsymmetricEdDSAPublicKey publicKey;
        if (nkey.isPair()) {
            byte[] pubBytes = nkey.getKeyPair().getPublic().getEncoded();
            publicKey = new AsymmetricEdDSAPublicKey(FipsEdEC.Ed25519.getAlgorithm(), pubBytes);
        }
        else {
            char[] encodedPublicKey = nkey.getPublicKey();
            byte[] decodedPublicKey = nkeyDecode(nkey.getType(), encodedPublicKey);
            publicKey = new AsymmetricEdDSAPublicKey(FipsEdEC.Ed25519.getAlgorithm(), decodedPublicKey);
        }

        FipsEdEC.EdDSAOperatorFactory factory = new FipsEdEC.EdDSAOperatorFactory();
        FipsOutputVerifier<FipsEdEC.Parameters> verifier = factory.createVerifier(publicKey, FipsEdEC.EdDSA);

        try {
            UpdateOutputStream stream = verifier.getVerifyingStream();
            stream.update(input, 0, input.length);
            stream.close();
            return verifier.isVerified(signature);
        }
        catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
