package org.bouncycastle.bcpg.test;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

public class PublicKeyPacketTest extends AbstractPacketTest
{
    @Override
    public String getName() {
        return "PublicKeyPacketTest";
    }

    @Override
    public void performTest() throws Exception {
        /*
        gen();
        /*/
        v4LegacyEd25519PublicKeyTest();
        v4LegacyEd25519WithLibrePgpOidPublicKeyTest();
        v4Ed448PublicKeyTest();

        v6Ed25519PublicKeyTest();
        v6Ed448PublicKeyTest();
        //*/
    }

    private void v4LegacyEd25519PublicKeyTest() throws IOException {
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

    private void v4LegacyEd25519WithLibrePgpOidPublicKeyTest() throws IOException {
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

    private void v4Ed448PublicKeyTest() throws IOException {
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
    }

    private void v6Ed25519PublicKeyTest() throws IOException {
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

    private void v6Ed448PublicKeyTest() throws IOException {
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

    private void gen() throws PGPException, IOException {
        Ed448KeyPairGenerator gen = new Ed448KeyPairGenerator();
        gen.init(new Ed448KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();

        Date date = new Date((new Date().getTime() / 1000) * 1000);
        System.out.println(date);
        BcPGPKeyConverter con = new BcPGPKeyConverter();
        PGPPublicKey pk = con.getPGPPublicKey(6, PublicKeyAlgorithmTags.Ed448, null, kp.getPublic(), date);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, PacketFormat.CURRENT);
        pk.encode(pOut);
        pOut.close();
        System.out.println(Hex.toHexString(bOut.toByteArray()));
    }

    public static void main(String[] args) {
        runTest(new PublicKeyPacketTest());
    }
}
