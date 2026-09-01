package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;

import java.util.ArrayList;
import java.util.List;

public class OpenPGPSmartCardUtils
{
    private final OpenPGPImplementation implementation;

    public OpenPGPSmartCardUtils(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
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
        if (secretKey.isMasterKey())
        {
            return new PGPSecretKey(
                    new SecretKeyPacket(
                            secretKey.getPublicKey().getPublicKeyPacket(),
                            locatorHint),
                    secretKey.getPublicKey());
        }
        else
        {
            return new PGPSecretKey(
                    new SecretSubkeyPacket(
                            (PublicSubkeyPacket) secretKey.getPublicKey().getPublicKeyPacket(),
                            locatorHint),
                    secretKey.getPublicKey());
        }
    }
}
