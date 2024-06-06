package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Date;

public class SecretKeyPacketTest
        extends AbstractPacketTest
{

    @Override
    public String getName()
    {
        return "SecretKeyPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        unencryptedV6Ed25519Key();
    }

    private void unencryptedV6Ed25519Key()
            throws IOException
    {
        // Test vector is the primary key taken from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-secret-key-transf
        String testVector = "c54b0663877fe31b00000020f94da7bb\n" +
                "48d60a61e567706a6587d0331999bb9d\n" +
                "891a08242ead84543df895a300197281\n" +
                "7b12be707e8d5f586ce61361201d344e\n" +
                "b266a2c82fde6835762b65b0b7";
        byte[] rawPubKey = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        byte[] rawSecKey = Hex.decode("1972817b12be707e8d5f586ce61361201d344eb266a2c82fde6835762b65b0b7");
        Date creationTime = hexDecodeDate("63877fe3");

        SecretKeyPacket packet = (SecretKeyPacket) hexDecodePacket(testVector);
        isEquals(PublicKeyPacket.VERSION_6, packet.getPublicKeyPacket().getVersion());
        isTrue(packet.hasNewPacketFormat());
        isEquals(creationTime, packet.getPublicKeyPacket().getTime());
        isEquals(PublicKeyAlgorithmTags.Ed25519, packet.getPublicKeyPacket().getAlgorithm());
        isEquals(SecretKeyPacket.USAGE_NONE, packet.getS2KUsage());
        isNull(packet.getIV());
        isNull(packet.getS2K());
        isEquals(0, packet.getAeadAlgorithm());
        isEquals(SymmetricKeyAlgorithmTags.NULL, packet.getEncAlgorithm());
        isEncodingEqual(rawPubKey, packet.getPublicKeyPacket().getKey().getEncoded());
        isEncodingEqual(rawSecKey, packet.getSecretKeyData());
        isEncodingEqual(Hex.decode(testVector), packet.getEncoded(PacketFormat.CURRENT));

        SecretKeyPacket sk = new SecretKeyPacket(
                new PublicKeyPacket(
                        PublicKeyPacket.VERSION_6,
                        PublicKeyAlgorithmTags.Ed25519,
                        creationTime,
                        new Ed25519PublicBCPGKey(rawPubKey)),
                SymmetricKeyAlgorithmTags.NULL,
                SecretKeyPacket.USAGE_NONE,
                null,
                null,
                rawSecKey);
        isEncodingEqual(Hex.decode(testVector), sk.getEncoded(PacketFormat.CURRENT));

        isFalse(hexDecodePacket(Hex.toHexString(sk.getEncoded(PacketFormat.LEGACY))).hasNewPacketFormat());
    }

    public static void main(String[] args)
    {
        runTest(new SecretKeyPacketTest());
    }
}