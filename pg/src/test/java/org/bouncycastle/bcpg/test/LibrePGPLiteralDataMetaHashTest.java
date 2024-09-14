package org.bouncycastle.bcpg.test;

import org.bouncycastle.bcpg.SignatureSubpacketInputStream;
import org.bouncycastle.bcpg.sig.LibrePGPLiteralDataMetaHash;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class LibrePGPLiteralDataMetaHashTest
        extends AbstractPacketTest
{
    @Override
    public String getName()
    {
        return "LibrePGPLiteralDataMetaHashTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        detachedSigMetadataTest();
        complexMetadataTest();
    }

    private void detachedSigMetadataTest()
            throws PGPException
    {
        LibrePGPLiteralDataMetaHash packet = LibrePGPLiteralDataMetaHash.createDetachedSignatureMetadata(
                false,
                new BcPGPDigestCalculatorProvider());
        isTrue("Could not verify LiteralDataMetaHash for detached signature.",
                packet.verify(
                PGPLiteralData.BINARY,
                new byte[0],
                0L,
                new JcaPGPDigestCalculatorProviderBuilder()
                        .setProvider(new BouncyCastleProvider())
                        .build()));
    }

    private void complexMetadataTest()
            throws PGPException, IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(Hex.decode("222800d7549da92db75e1f544f36bb75933fadd94c2aee04d4bfd617ff868e27d037a0"));
        SignatureSubpacketInputStream pIn = new SignatureSubpacketInputStream(bIn);

        LibrePGPLiteralDataMetaHash packet = (LibrePGPLiteralDataMetaHash) pIn.readPacket();

        isTrue(packet.verify(
                PGPLiteralData.UTF8,
                Strings.toUTF8ByteArray("english_paris_agreement.pdf"),
                1490887073,
                new BcPGPDigestCalculatorProvider()
        ));

        isFalse(packet.verify(
                PGPLiteralData.UTF8,
                Strings.toUTF8ByteArray("foo_bar.pdf"),
                1234567890,
                new BcPGPDigestCalculatorProvider())
        );
    }

    public static void main(String[] args)
    {
        runTest(new LibrePGPLiteralDataMetaHashTest());
    }
}
