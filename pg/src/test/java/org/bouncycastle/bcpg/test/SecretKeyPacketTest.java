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
        aeadEncryptedSecretKey();
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

    private void aeadEncryptedSecretKey()
            throws IOException
    {
        String testVector = "c5820663877fe31b00000020f94da7bb" +
                "48d60a61e567706a6587d0331999bb9d" +
                "891a08242ead84543df895a3fd260902" +
                "14045d6fd71c9e096d1eb6917b6e6e1e" +
                "ecae010415b4a8a9274fabe632f875a7" +
                "0659202178258fa484d88b27f220e3d2" +
                "de0203ca0f1feecb6b775381e3e2d9b1" +
                "485c22338ca551e09a263f22eb4992e9" +
                "677a8058";
        byte[] rawPubKey = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        Date creationTime = hexDecodeDate("63877fe3");
        byte[] argon2Salt = Hex.decode("5d6fd71c9e096d1eb6917b6e6e1eecae");
        byte[] aeadIv = Hex.decode("b4a8a9274fabe632f875a706592021");
        byte[] encryptedSecKey = Hex.decode("78258fa484d88b27f220e3d2de0203ca0f1feecb6b775381e3e2d9b1485c22338ca551e09a263f22eb4992e9677a8058");

        SecretKeyPacket packet = (SecretKeyPacket) hexDecodePacket(testVector);
        isEquals("S2K usage mismatch", SecretKeyPacket.USAGE_AEAD, packet.getS2KUsage());
        isEquals("Symmetric enc algorithm mismatch", SymmetricKeyAlgorithmTags.AES_256, packet.getEncAlgorithm());
        isEquals("AEAD algorithm mismatch", AEADAlgorithmTags.OCB, packet.getAeadAlgorithm());
        S2K s2k = packet.getS2K();
        isEncodingEqual("Argon2 salt (s2k iv) mismatch", argon2Salt, s2k.getIV());
        isEquals("Argon2 parallelism (p) mismatch", 4, s2k.getParallelism());
        isEquals("Argon2 passes (t) mismatch", 1, s2k.getPasses());
        isEquals("Argon2 memory exponent (m) mismatch", 21, s2k.getMemorySizeExponent());
        isEncodingEqual("IV mismatch", aeadIv, packet.getIV());
        isEncodingEqual("Encrypted MPIs mismatch", encryptedSecKey, packet.getSecretKeyData());
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), packet.getEncoded(PacketFormat.CURRENT));

        SecretKeyPacket p = new SecretKeyPacket(
                new PublicKeyPacket(
                        PublicKeyPacket.VERSION_6,
                        PublicKeyAlgorithmTags.Ed25519,
                        creationTime,
                        new Ed25519PublicBCPGKey(rawPubKey)),
                SymmetricKeyAlgorithmTags.AES_256,
                AEADAlgorithmTags.OCB,
                SecretKeyPacket.USAGE_AEAD,
                new S2K(new S2K.Argon2Params(argon2Salt, 1, 4, 21)),
                aeadIv,
                encryptedSecKey
        );
        isEncodingEqual(Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));
    }

    public static void main(String[] args)
    {
        runTest(new SecretKeyPacketTest());
    }
}