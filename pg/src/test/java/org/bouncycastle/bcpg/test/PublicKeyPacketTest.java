package org.bouncycastle.bcpg.test;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

public class PublicKeyPacketTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "PublicKeyPacketTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        /*
        gen();
        /*/
        v4LegacyEd25519PublicKeyTest();
        v4LegacyEd25519WithLibrePgpOidPublicKeyTest();
        v4Ed448PublicKeyTest();
        v4LegacyEd448PublicKeyTest();
        v4RsaPublicKey();

        v6Ed25519PublicKeyTest();
        v6Ed448PublicKeyTest();

        v6PublicKeyWithKeyTooLong();
        v6PublicKeyWithKeyTooShort();
        v6Ed25519KeyWithWrongLength();
        //*/
    }

    /**
     * Parse a version 4 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#EDDSA_LEGACY},
     * containing an Ed25519 key.
     * The curve OID is {@link GNUObjectIdentifiers#Ed25519}, which is compliant to the official spec.
     *
     * @throws IOException not expected
     */
    private void v4LegacyEd25519PublicKeyTest()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-key
        String testVector = "98330453f35f0b16092b06010401da47\n" +
                "0f010107403f098994bdd916ed405319\n" +
                "7934e4a87c80733a1280d62f8010992e\n" +
                "43ee3b2406";
        // Compare parsed packet to expectations
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_4, packet.getVersion());
        isFalse("Packet format mismatch", packet.hasNewPacketFormat());
        isEquals(parseUTCDate("2014-08-19 14:28:27 UTC"), packet.getTime());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.EDDSA_LEGACY, packet.getAlgorithm());
        isTrue("Key class mismatch", packet.getKey() instanceof EdDSAPublicBCPGKey);

        // Manually construct packet and compare encoding
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                parseUTCDate("2014-08-19 14:28:27 UTC"),
                new EdDSAPublicBCPGKey(
                        GNUObjectIdentifiers.Ed25519,
                        new BigInteger(1, Hex.decode("403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406")))
        );
        isEncodingEqual(Hex.decode(testVector), p.getEncoded(PacketFormat.LEGACY));
    }

    /**
     * Parse a version 4 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#EDDSA_LEGACY},
     * containing an Ed25519 key.
     * The curve OID was altered to the non-standard {@link EdECObjectIdentifiers#id_Ed25519}, which is introduced
     * by LibrePGP.
     *
     * @throws IOException not expected
     */
    private void v4LegacyEd25519WithLibrePgpOidPublicKeyTest()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v4-ed25519legacy-key
        // but with the OID replaced from 1.3.6.1.4.1.11591.15.1 to 1.3.101.112
        String testVector = "982d0453f35f0b16032b65700107403f\n" +
                "098994bdd916ed4053197934e4a87c80\n" +
                "733a1280d62f8010992e43ee3b2406";
        // Compare parsed packet to expectations
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_4, packet.getVersion());
        isFalse("Packet format mismatch", packet.hasNewPacketFormat());
        isEquals(parseUTCDate("2014-08-19 14:28:27 UTC"), packet.getTime());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.EDDSA_LEGACY, packet.getAlgorithm());
        isTrue("Key class mismatch", packet.getKey() instanceof EdDSAPublicBCPGKey);

        // Manually construct packet and compare encoding
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                parseUTCDate("2014-08-19 14:28:27 UTC"),
                new EdDSAPublicBCPGKey(
                        EdECObjectIdentifiers.id_Ed25519,
                        new BigInteger(1, Hex.decode("403f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406")))
        );
        isEncodingEqual(Hex.decode(testVector), p.getEncoded(PacketFormat.LEGACY));
    }

    /**
     * Parse a version 4 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#Ed448} containing an Ed448 key.
     *
     * @throws IOException not expected
     */
    private void v4Ed448PublicKeyTest()
            throws IOException
    {
        String testVector = "c63f04665ef3281c162270f9f44aa773e3f71e5ebb2e87648f3a6d89a729bd388b802fe0e72ffd58ec3ffbad9600386f987f8aa764c7b8f5a0ec640f163c047600";
        String rawKey = "162270f9f44aa773e3f71e5ebb2e87648f3a6d89a729bd388b802fe0e72ffd58ec3ffbad9600386f987f8aa764c7b8f5a0ec640f163c047600";
        Date creationTime = parseUTCDate("2024-06-04 10:57:44 UTC");

        // Compare parsed packet to expectations
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_4, packet.getVersion());
        isTrue("Packet format mismatch", packet.hasNewPacketFormat());
        isEquals("Creation time mismatch " + packet.getTime(), creationTime, packet.getTime());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.Ed448, packet.getAlgorithm());
        isTrue("Key class mismatch", packet.getKey() instanceof Ed448PublicBCPGKey);
        isEncodingEqual("Raw key encoding mismatch", Hex.decode(rawKey), packet.getKey().getEncoded());

        // Manually construct packet and compare encoding
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.Ed448,
                creationTime,
                new Ed448PublicBCPGKey(Hex.decode(rawKey))
        );
        isEncodingEqual("Encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));

        isFalse(hexDecodePacket(Hex.toHexString(p.getEncoded(PacketFormat.LEGACY))).hasNewPacketFormat());
    }

    /**
     * Parse a version 4 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#EDDSA_LEGACY},
     * containing an Ed448 key.
     * Such keys are non-standard and were introduced by LibrePGP.
     *
     * @throws IOException not expected
     */
    private void v4LegacyEd448PublicKeyTest()
            throws IOException
    {
        String testVector = "c646046660304e16032b657101cf40e67866b5de564a9d65d8988972a314e2853db8c5f1f09fbb4e8c1ec8f2c621f9ffe241ff92454df7c0ffb634ba52e5336cebd96a2008aa5d00";
        byte[] rawKey = Hex.decode("40e67866b5de564a9d65d8988972a314e2853db8c5f1f09fbb4e8c1ec8f2c621f9ffe241ff92454df7c0ffb634ba52e5336cebd96a2008aa5d00");
        Date creationTime = parseUTCDate("2024-06-05 09:30:54 UTC");

        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_4, packet.getVersion());
        isTrue("Packet length encoding format mismatch", packet.hasNewPacketFormat());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.EDDSA_LEGACY, packet.getAlgorithm());
        isEquals("Creation time mismatch", creationTime, packet.getTime());
        isTrue("Key class mismatch", packet.getKey() instanceof EdDSAPublicBCPGKey);
        byte[] idEd448 = Arrays.copyOfRange(EdECObjectIdentifiers.id_Ed448.getEncoded(), 1, EdECObjectIdentifiers.id_Ed448.getEncoded().length);
        isTrue("Key encoding MUST have Ed448 OID (without first octet) prefixed", Arrays.areEqual(
                idEd448, 0, idEd448.length - 1,
                packet.getKey().getEncoded(), 0, idEd448.length - 1));
        isEncodingEqual("Parsed packet encoding mismatch", Hex.decode(testVector), packet.getEncoded(PacketFormat.CURRENT));

        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_4,
                PublicKeyAlgorithmTags.EDDSA_LEGACY,
                creationTime,
                new EdDSAPublicBCPGKey(EdECObjectIdentifiers.id_Ed448, new BigInteger(1, rawKey))
        );
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));
    }

    private void v4RsaPublicKey() throws IOException {
        String testVector = "99018d045da59cf2010c00b970bf4f42\n" +
                "840b4ccba18db62f6f835cbaea346df9\n" +
                "a03d1172c17e778cf86815fe1983a9af\n" +
                "fec78e5e981e71374e715b6d7f30bcc9\n" +
                "c20aaeddda4138b0386fdcb5a478064f\n" +
                "ede9ac8d15f7543711d69385822b3773\n" +
                "ff9e9f5b63b4176dea21177c514269e4\n" +
                "82253784437510ad761550200bb3be9d\n" +
                "a8572fcb692da4c50a0abe987fe6943f\n" +
                "e7086ab32ae81160c9a12574c8e6f6e4\n" +
                "1fe2c24fe92d4168ca10c6f5b8f4908c\n" +
                "c3c6b12a5beec16bc9e871095e70c177\n" +
                "5f928c379929db3ada2eff5d94106959\n" +
                "6e375e4b63702660332db44a8bab6959\n" +
                "9af097bf102c14598522019c4b22532f\n" +
                "f42bab10eb71530e8ddd174eb4b99865\n" +
                "2f6e1279f9cb552417cf28f0d92ef3dd\n" +
                "2e93a06b7b01732722c0c79c11678174\n" +
                "a95ff2ab7e94590d0907f0141a11d53d\n" +
                "d15fea997a79ac41c13e465ef6c15226\n" +
                "ed7fc608da883946c8135ad5df53b79b\n" +
                "4865eb97964ca5b03a99b7e177447c68\n" +
                "fc567e60d68883a106e7e1302bd41e1d\n" +
                "6c02930a5599ef21f7fdff40dc6b7c1b\n" +
                "bcb2306b74f80b2b217d3d0011010001";
        Date creationTime = hexDecodeDate("5da59cf2");
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);

        isFalse(packet.hasNewPacketFormat());
        isEquals(PublicKeyPacket.VERSION_4, packet.getVersion());
        isEquals(PublicKeyAlgorithmTags.RSA_GENERAL, packet.getAlgorithm());
        isEquals(creationTime, packet.getTime());
        isTrue(packet.getKey() instanceof RSAPublicBCPGKey);
        RSAPublicBCPGKey k = (RSAPublicBCPGKey) packet.getKey();
        isEquals(BigInteger.valueOf(0x10001), k.getPublicExponent());

        isEncodingEqual(Hex.decode(testVector), packet.getEncoded(PacketFormat.LEGACY));
    }

    /**
     * Parse a version 6 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#Ed25519}.
     *
     * @throws IOException not expected
     */
    private void v6Ed25519PublicKeyTest()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        String testVector =
                "c62a0663877fe31b00000020f94da7bb\n" +
                        "48d60a61e567706a6587d0331999bb9d\n" +
                        "891a08242ead84543df895a3";
        byte[] rawKey = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");

        // Construct key manually and compare encoding
        Date creationTime = hexDecodeDate("63877fe3");
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.Ed25519,
                creationTime,
                new Ed25519PublicBCPGKey(rawKey));
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));

        // Parse key from test vector and compare against expectations
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);

        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_6, packet.getVersion());
        isTrue("Packet format mismatch", packet.hasNewPacketFormat());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.Ed25519, packet.getAlgorithm());
        isEquals("Creation time mismatch", creationTime, packet.getTime());
        isEncodingEqual("Raw key encoding mismatch", rawKey, packet.getKey().getEncoded());
        isTrue("Key class mismatch", packet.getKey() instanceof Ed25519PublicBCPGKey);
    }

    /**
     * Parse a version 6 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#Ed448}.
     *
     * @throws IOException not expected
     */
    private void v6Ed448PublicKeyTest()
            throws IOException
    {
        String testVector = "c64306665ef5f31c0000003955ffd7f894397e43db739ae08250fe82f06a4206651d37538efe426d45c82f277d74841b29383e1b21ab930e85b8ac3b3b60d7c6a03effe880";
        String rawKey = "55ffd7f894397e43db739ae08250fe82f06a4206651d37538efe426d45c82f277d74841b29383e1b21ab930e85b8ac3b3b60d7c6a03effe880";
        Date creationTime = parseUTCDate("2024-06-04 11:09:39 UTC");

        // Compare parsed packet to expectations
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEquals("Packet version mismatch", PublicKeyPacket.VERSION_6, packet.getVersion());
        isTrue("Packet format mismatch", packet.hasNewPacketFormat());
        isEquals("Creation time mismatch " + formatUTCDate(packet.getTime()), creationTime, packet.getTime());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.Ed448, packet.getAlgorithm());
        isTrue("Key class mismatch", packet.getKey() instanceof Ed448PublicBCPGKey);
        isEncodingEqual("Raw key encoding mismatch", Hex.decode(rawKey), packet.getKey().getEncoded());

        // Manually construct packet and compare encoding
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.Ed448,
                creationTime,
                new Ed448PublicBCPGKey(Hex.decode(rawKey))
        );
        isEncodingEqual("Encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));
    }

    /**
     * Test behavior when parsing a version 6 OpenPGP key, where the key material is truncated.
     * In this case, 4 octets have been removed from the key material field (decreasing the length to 28 octets).
     * The packet length octet has been adjusted to the new length, but the keyOctets=32 field is kept the same.
     * An {@link EOFException} is expected, since the parser tries to parse 32 key material octets, but can only read 28.
     *
     * @throws IOException not expected
     */
    private void v6PublicKeyWithKeyTooShort()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        // but with 4 octets removed from the end and decreased packet length.
        String testVector =
                "c6260663877fe31b00000020f94da7bb\n" +
                        "48d60a61e567706a6587d0331999bb9d\n" +
                        "891a08242ead8454";
        try
        {
            hexDecodePacket(testVector);
            fail("Expected EOF exception, since we can't fully read a key too short.");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    /**
     * Test behavior when parsing a version 6 OpenPGP packet where some bytes were appended to the key material.
     * The packet length counter has been adjusted, but the key material length counter has not.
     * No exception is expected, since the keyOctets counter is used to determine the length of the key material.
     *
     * @throws IOException not expected
     */
    private void v6PublicKeyWithKeyTooLong()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        // but with 4 octets appended octets at the end and increased packet length.
        String testVector =
                "c62e0663877fe31b00000020f94da7bb\n" +
                        "48d60a61e567706a6587d0331999bb9d\n" +
                        "891a08242ead84543df895a301020304";
        byte[] rawKey = Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3");
        PublicKeyPacket packet = (PublicKeyPacket) hexDecodePacket(testVector);
        isEncodingEqual("Appended octets MUST not be part of the parsed key",
                rawKey, packet.getKey().getEncoded());
    }

    /**
     * Test behavior when parsing a version 6 OpenPGP key with algorithm ID {@link PublicKeyAlgorithmTags#Ed25519},
     * but with truncated key material. Instead of 32 octets, the key only consists of 31. The keyOctets counter
     * and packet length have been adjusted accordingly.
     * An {@link EOFException} is expected, since Ed25519 always uses 32 octets.
     *
     * @throws IOException not expected
     */
    private void v6Ed25519KeyWithWrongLength()
            throws IOException
    {
        // Test vector is the primary key extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        // but with 1 octet stripped from the end and adjusted packet length and key material counters.
        String testVector =
                "c6290663877fe31b0000001ff94da7bb\n" +
                        "48d60a61e567706a6587d0331999bb9d\n" +
                        "891a08242ead84543df895";
        try
        {
            hexDecodePacket(testVector);
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    private void gen()
            throws PGPException, IOException
    {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001),
                CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048)));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        Date date = new Date((new Date().getTime() / 1000) * 1000);
        System.out.println(formatUTCDate(date));
        BcPGPKeyConverter con = new BcPGPKeyConverter();
        PGPPublicKey pk = con.getPGPPublicKey(4, PublicKeyAlgorithmTags.RSA_GENERAL, null, kp.getPublic(), date);
        // pk = new PGPPublicKey(new PublicSubkeyPacket(pk.getVersion(), pk.getAlgorithm(), pk.getCreationTime(), pk.getPublicKeyPacket().getKey()), new BcKeyFingerprintCalculator());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.CURRENT);
        pk.encode(pOut);
        pOut.close();
        System.out.println(Hex.toHexString(bOut.toByteArray()));

        bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = new ArmoredOutputStream(bOut);
        pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        pk.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut.toString());
    }

    public static void main(String[] args)
    {
        runTest(new PublicKeyPacketTest());
    }
}
