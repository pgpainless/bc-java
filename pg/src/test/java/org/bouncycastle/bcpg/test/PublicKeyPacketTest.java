package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.test.DumpUtil;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Date;

public class PublicKeyPacketTest extends AbstractPacketTest
{
    @Override
    public String getName() {
        return "PublicKeyPacketTest";
    }

    @Override
    public void performTest() throws Exception {
        v6PublicKeyTest();
    }

    private void v6PublicKeyTest() throws IOException {
        String testVector = "" +
                "c62a0663877fe31b00000020f94da7bb\n" +
                "48d60a61e567706a6587d0331999bb9d\n" +
                "891a08242ead84543df895a3";

        Date creationTime = hexDecodeDate("63877fe3");
        PublicKeyPacket p = new PublicKeyPacket(
                PublicKeyPacket.VERSION_6,
                PublicKeyAlgorithmTags.Ed25519,
                creationTime,
                new Ed25519PublicBCPGKey(Hex.decode("f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3")));

        byte[] encoding = p.getEncoded(PacketFormat.CURRENT);
        isEncodingEqual(Hex.decode(testVector), encoding);
    }

    public static void main(String[] args) {
        runTest(new PublicKeyPacketTest());
    }
}
