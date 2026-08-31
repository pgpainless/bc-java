package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPKeyPairGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

import java.security.PublicKey;
import java.util.Date;

public class EDECPublicKeyConverterTest
    extends SimpleTest
{
    private final Date date = new Date();
    private final PGPKeyPairGenerator kpGen;
    private final BcPGPKeyConverter bcKeyConverter;
    private final JcaPGPKeyConverter jcaKeyConverter;

    public EDECPublicKeyConverterTest()
    {
        BouncyCastleProvider prov = new BouncyCastleProvider();
        bcKeyConverter = new BcPGPKeyConverter();
        jcaKeyConverter = new JcaPGPKeyConverter()
                .setProvider(prov);
        kpGen = new BcPGPKeyPairGeneratorProvider()
                .get(4, date);
    }

    @Override
    public String getName()
    {
        return "EDECPublicKeyConverterTest";
    }

    @Override
    public void performTest()
            throws Exception
    {
        // Encryption
        testKeyConversion(kpGen.generateX25519KeyPair(), "X25519");
        testKeyConversion(kpGen.generateX448KeyPair(), "X448");

        testKeyConversion(kpGen.generateNistP256ECDHKeyPair(), "Nist-P256 ECDH");
        testKeyConversion(kpGen.generateNistP384ECDHKeyPair(), "Nist-P384 ECDH");
        testKeyConversion(kpGen.generateNistP521ECDHKeyPair(), "Nist-P521 ECDH");

        testKeyConversion(kpGen.generateBrainpoolP256r1ECDHKeyPair(), "Brainpool-P256r1 ECDH");
        testKeyConversion(kpGen.generateBrainpoolP384r1ECDHKeyPair(), "Brainpool-P384r1 ECDH");
        testKeyConversion(kpGen.generateBrainpoolP512r1ECDHKeyPair(), "Brainpool-P512r1 ECDH");

        // Signature
        testKeyConversion(kpGen.generateEd25519KeyPair(), "Ed25519");
        testKeyConversion(kpGen.generateEd448KeyPair(), "Ed448");

        testKeyConversion(kpGen.generateNistP256ECDSAKeyPair(), "Nist-P256 ECDSA");
        testKeyConversion(kpGen.generateNistP384ECDSAKeyPair(), "Nist-P384 ECDSA");
        testKeyConversion(kpGen.generateNistP521ECDSAKeyPair(), "Nist-P521 ECDSA");

        testKeyConversion(kpGen.generateBrainpoolP256r1ECDSAKeyPair(), "Brainpool-P256r1 ECDSA");
        testKeyConversion(kpGen.generateBrainpoolP384r1ECDSAKeyPair(), "Brainpool-P384r1 ECDSA");
        testKeyConversion(kpGen.generateBrainpoolP512r1ECDSAKeyPair(), "Brainpool-P512r1 ECDSA");
    }

    private void testKeyConversion(PGPKeyPair pgpKeyPair, String name)
            throws PGPException
    {
        PGPPublicKey pgpPubKey = pgpKeyPair.getPublicKey();

        AsymmetricKeyParameter bcPubKey = bcKeyConverter.getPublicKey(pgpPubKey);
        PublicKey jcaPubKey = jcaKeyConverter.getPublicKey(pgpPubKey);

        PublicKey converted = EDECPublicKeyConverter.toPublicKey(bcPubKey);
        isTrue("Converted " + name + " public key does not match expectations.",
                Arrays.areEqual(jcaPubKey.getEncoded(), converted.getEncoded()));
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new EDECPublicKeyConverterTest());
    }
}
