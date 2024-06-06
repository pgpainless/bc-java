package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Date;

public class SecretSubkeyPacketTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "SecretSubkeyPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        unencryptedV6X25519Subkey();
    }

    private void unencryptedV6X25519Subkey()
            throws IOException
    {
        String testVector = "c74b0663877fe3190000002086932483\n" +
                "67f9e5015db922f8f48095dda784987f\n" +
                "2d5985b12fbad16caf5e4435004d600a\n" +
                "4f794d44775c57a26e0feefed558e9af\n" +
                "ffd6ad0d582d57fb2ba2dcedb8";
        Date creationTime = hexDecodeDate("63877fe3");
        byte[] rawPubKey = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        byte[] rawSecKey = Hex.decode("4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8");

        SecretSubkeyPacket packet = (SecretSubkeyPacket) hexDecodePacket(testVector);
        isEquals(PublicKeyPacket.VERSION_6, packet.getPublicKeyPacket().getVersion());
        isTrue(packet.hasNewPacketFormat());
        isEquals(PublicKeyAlgorithmTags.X25519, packet.getPublicKeyPacket().getAlgorithm());
        isEquals(creationTime, packet.getPublicKeyPacket().getTime());
        isEquals(SecretSubkeyPacket.USAGE_NONE, packet.getS2KUsage());
        isNull(packet.getIV());
        isNull(packet.getS2K());
        isEquals(0, packet.getAeadAlgorithm());
        isEquals(SymmetricKeyAlgorithmTags.NULL, packet.getEncAlgorithm());
        isEncodingEqual(rawPubKey, packet.getPublicKeyPacket().getKey().getEncoded());
        isEncodingEqual(rawSecKey, packet.getSecretKeyData());
        isEncodingEqual(Hex.decode(testVector), packet.getEncoded(PacketFormat.CURRENT));

        SecretSubkeyPacket sk = new SecretSubkeyPacket(
                new PublicSubkeyPacket(
                        PublicKeyPacket.VERSION_6,
                        PublicKeyAlgorithmTags.X25519,
                        creationTime,
                        new X25519PublicBCPGKey(rawPubKey)),
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
        runTest(new SecretSubkeyPacketTest());
    }
}
