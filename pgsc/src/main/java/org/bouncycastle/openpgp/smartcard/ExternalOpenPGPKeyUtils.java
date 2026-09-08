package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;

import java.util.ArrayList;
import java.util.List;

public class ExternalOpenPGPKeyUtils
{
    private final OpenPGPImplementation implementation;

    public ExternalOpenPGPKeyUtils(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
    }

    public OpenPGPKey fromCertificate(OpenPGPCertificate certificate)
    {
        return fromCertificate(certificate, null);
    }

    public OpenPGPKey fromCertificate(OpenPGPCertificate certificate, byte[] locatorHint)
    {
        List<PGPSecretKey> keys = new ArrayList<>();
        for (OpenPGPCertificate.OpenPGPComponentKey componentKey : certificate.getKeys())
        {
            PGPPublicKey publicKey = componentKey.getPGPPublicKey();
            keys.add(toExternalKey(publicKey, locatorHint));
        }

        return new OpenPGPKey(new PGPSecretKeyRing(keys));
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key)
    {
        return toExternalKey(key, (byte[]) null);
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key, byte[] locatorHint)
    {
        List<OpenPGPKey.OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPKey.OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            secretKeys.add(new OpenPGPKey.OpenPGPSecretKey(
                    sk.getPublicKey(),
                    toExternalKey(sk.getPGPSecretKey(), locatorHint),
                    implementation.pbeSecretKeyDecryptorBuilderProvider()));
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    public OpenPGPKey.OpenPGPSecretKey toExternalKey(OpenPGPKey.OpenPGPSecretKey key, byte[] locatorHint)
    {
        PGPSecretKey externalKey = toExternalKey(key.getPGPSecretKey(), locatorHint);
        return new OpenPGPKey.OpenPGPSecretKey(key.getPublicKey(), externalKey, implementation.pbeSecretKeyDecryptorBuilderProvider());
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey)
    {
        return toExternalKey(key, componentKey, null);
    }

    public OpenPGPKey toExternalKey(OpenPGPKey key, KeyIdentifier componentKey, byte[] locatorHint)
    {
        List<OpenPGPKey.OpenPGPSecretKey> secretKeys = new ArrayList<>();
        for (OpenPGPKey.OpenPGPSecretKey sk : key.getSecretKeys().values())
        {
            if (sk.getKeyIdentifier().matchesExplicit(componentKey))
            {
                secretKeys.add(new OpenPGPKey.OpenPGPSecretKey(
                        sk.getPublicKey(),
                        toExternalKey(sk.getPGPSecretKey(), locatorHint),
                        implementation.pbeSecretKeyDecryptorBuilderProvider()));
            }
            else
            {
                secretKeys.add(sk);
            }
        }
        return new OpenPGPKey(secretKeys, implementation);
    }

    public PGPSecretKey toExternalKey(PGPSecretKey secretKey, byte[] locatorHint)
    {
        return toExternalKey(secretKey.getPublicKey(), locatorHint);
    }

    public PGPSecretKey toExternalKey(PGPPublicKey publicKey, byte[] locatorHint)
    {
        if (publicKey.isMasterKey())
        {
            return new PGPSecretKey(
                    new SecretKeyPacket(
                            publicKey.getPublicKeyPacket(),
                            locatorHint),
                    publicKey);
        }
        else
        {
            return new PGPSecretKey(
                    new SecretSubkeyPacket(
                            (PublicSubkeyPacket) publicKey.getPublicKeyPacket(),
                            locatorHint),
                    publicKey);
        }
    }
}
