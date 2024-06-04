package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Date;

public class PublicSubkeyPacketTest extends AbstractPacketTest {

    @Override
    public String getName() {
        return "PublicSubkeyPacketTest";
    }

    @Override
    public void performTest() throws Exception {
        v6X25519PublicSubkeyTest();
        v6X448PublicSubkeyTest();
    }

    private void v6X25519PublicSubkeyTest() throws IOException {
        // Test vector is the subkey extracted from here:
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-sample-v6-certificate-trans
        String testVector = "ce2a0663877fe3190000002086932483" +
                "67f9e5015db922f8f48095dda784987f" +
                "2d5985b12fbad16caf5e4435";
        byte[] rawKey = Hex.decode("8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435");

        Date creationTime = hexDecodeDate("63877fe3");
        PublicSubkeyPacket p = new PublicSubkeyPacket(
                PublicSubkeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.X25519,
                creationTime,
                new X25519PublicBCPGKey(rawKey));
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));

        // Parse key from test vector and compare against expectations
        PublicSubkeyPacket packet = (PublicSubkeyPacket) hexDecodePacket(testVector);

        isEquals("Packet version mismatch", PublicSubkeyPacket.VERSION_6, packet.getVersion());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.X25519, packet.getAlgorithm());
        isEquals("Creation time mismatch", creationTime, packet.getTime());
        isEncodingEqual("Raw key encoding mismatch", rawKey, packet.getKey().getEncoded());
        isTrue("Key class mismatch", packet.getKey() instanceof X25519PublicBCPGKey);
    }

    private void v6X448PublicSubkeyTest() throws IOException {
        String testVector = "ce4206665f08c11a0000003884e8081b81e122b8992c8188794ea86bae6549549eaeb864ab6619deae39fd6ebb9db4209fce795b4de3baab0a86ddde38653d7021d16db5";
        Date creationTime = parseUTCDate("2024-06-04 12:29:53 UTC");
        byte[] rawKey = Hex.decode("84e8081b81e122b8992c8188794ea86bae6549549eaeb864ab6619deae39fd6ebb9db4209fce795b4de3baab0a86ddde38653d7021d16db5");

        // Parse key from test vector and compare against expectations
        PublicSubkeyPacket packet = (PublicSubkeyPacket) hexDecodePacket(testVector);

        isEquals("Packet version mismatch", PublicSubkeyPacket.VERSION_6, packet.getVersion());
        isEquals("Public key algorithm mismatch", PublicKeyAlgorithmTags.X448, packet.getAlgorithm());
        isEquals("Creation time mismatch", creationTime, packet.getTime());
        isEncodingEqual("Raw key encoding mismatch", rawKey, packet.getKey().getEncoded());
        isTrue("Key class mismatch", packet.getKey() instanceof X448PublicBCPGKey);

        PublicSubkeyPacket p = new PublicSubkeyPacket(
                PublicSubkeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.X448,
                creationTime,
                new X448PublicBCPGKey(rawKey));
        isEncodingEqual("Packet encoding mismatch", Hex.decode(testVector), p.getEncoded(PacketFormat.CURRENT));
    }

    public static void main(String[] args) {
        runTest(new PublicSubkeyPacketTest());
    }
}
