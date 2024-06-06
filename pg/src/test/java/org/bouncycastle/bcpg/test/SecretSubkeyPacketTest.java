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
        aeadEncryptedV6X25519Subkey();
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

    private void aeadEncryptedV6X25519Subkey() throws IOException {
        String testVector = "c7820663877fe3190000002086932483" +
                "67f9e5015db922f8f48095dda784987f" +
                "2d5985b12fbad16caf5e4435fd260902" +
                "14040e61846829da869abe0ea61545dc" +
                "14cc0104152e13ca9ff4e724fb1c2eb1" +
                "df86020941af92d5cabfe5ba9df1c50b" +
                "c75c54a38c0da16977e837ac54191743" +
                "10723afae7af2a3551bf9a00c60bbb78" +
                "9a5a5cd8";
        Date creationTime = hexDecodeDate("63877fe3");
        byte[] rawPubKey = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");
        byte[] encSecKey = Hex.decode("41af92d5cabfe5ba9df1c50bc75c54a38c0da16977e837ac5419174310723afae7af2a3551bf9a00c60bbb789a5a5cd8");
        byte[] argon2Salt = Hex.decode("0e61846829da869abe0ea61545dc14cc");
        byte[] aeadIv = Hex.decode("2e13ca9ff4e724fb1c2eb1df860209");

        SecretSubkeyPacket packet = (SecretSubkeyPacket) hexDecodePacket(testVector);
        isTrue("Packet length encoding format mismatch", packet.hasNewPacketFormat());
        isEquals("S2K usage mismatch", SecretKeyPacket.USAGE_AEAD, packet.getS2KUsage());
        isEquals("Symmetric enc algorithm mismatch", SymmetricKeyAlgorithmTags.AES_256, packet.getEncAlgorithm());
        isEquals("AEAD algorithm mismatch", AEADAlgorithmTags.OCB, packet.getAeadAlgorithm());
        S2K s2k = packet.getS2K();
        isEncodingEqual("Argon2 salt (s2k iv) mismatch", argon2Salt, s2k.getIV());
        isEquals("Argon2 passes (t) mismatch", 1, s2k.getPasses());
        isEquals("Argon2 parallelism (p) mismatch", 4, s2k.getParallelism());
        isEquals("Argon2 memory exponent (m) mismatch", 21, s2k.getMemorySizeExponent());
        isEncodingEqual("IV mismatch", aeadIv, packet.getIV());
        isEncodingEqual("Encrypted MPIs mismatch", encSecKey, packet.getSecretKeyData());
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), packet.getEncoded(PacketFormat.CURRENT));

        SecretSubkeyPacket p = new SecretSubkeyPacket(
                new PublicSubkeyPacket(
                        PublicKeyPacket.VERSION_6,
                        PublicKeyAlgorithmTags.X25519,
                        creationTime,
                        new X25519PublicBCPGKey(rawPubKey)),
                SymmetricKeyAlgorithmTags.AES_256,
                AEADAlgorithmTags.OCB,
                SecretKeyPacket.USAGE_AEAD,
                new S2K(new S2K.Argon2Params(argon2Salt, 1, 4, 21)),
                aeadIv,
                encSecKey);
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));
    }

    public static void main(String[] args)
    {
        runTest(new SecretSubkeyPacketTest());
    }
}
