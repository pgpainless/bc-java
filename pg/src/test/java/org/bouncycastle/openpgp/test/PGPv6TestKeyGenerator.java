package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketFormat;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.util.test.SimpleTest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class PGPv6TestKeyGenerator
        extends SimpleTest
{
    @Override
    public String getName()
    {
        return "PGPv6TestKeyGenerator";
    }

    @Override
    public void performTest()
            throws Exception
    {
        generateEd448X448Key();
    }


    private void generateEd448X448Key()
            throws PGPException, IOException
    {
        Date creationTime = new Date((new Date().getTime() / 1000) * 1000);
        String uid = "Ed <ed448@example.com>";

        Ed448KeyPairGenerator edKpGen = new Ed448KeyPairGenerator();
        edKpGen.init(new Ed448KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair edKp = edKpGen.generateKeyPair();
        PGPKeyPair edPgpKp = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.Ed448, edKp, creationTime);
        PGPPublicKey primaryPublicKey = edPgpKp.getPublicKey();
        PGPPrivateKey primaryPrivateKey = edPgpKp.getPrivateKey();

        PGPSignatureGenerator dkSigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(primaryPublicKey.getAlgorithm(), HashAlgorithmTags.SHA3_512),
                primaryPublicKey);
        dkSigGen.init(PGPSignature.DIRECT_KEY, primaryPrivateKey);
        List<SignatureSubpacket> subpackets = new ArrayList<>();
        subpackets.add(new SignatureCreationTime(true, creationTime));
        subpackets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS, false,
                new int[]{SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.AES_128}));
        subpackets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS, false,
                new int[]{HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_512, HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA3_256}));
        subpackets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS, false,
                new int[]{CompressionAlgorithmTags.UNCOMPRESSED}));
        subpackets.add(new KeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA));
        subpackets.add(new Features(false, Features.FEATURE_MODIFICATION_DETECTION | Features.FEATURE_SEIPD_V2));
        subpackets.add(new IssuerFingerprint(false, primaryPublicKey.getVersion(), primaryPublicKey.getFingerprint()));
        subpackets.add(new PreferredAEADCiphersuites(false, new PreferredAEADCiphersuites.Combination[]{
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
                new PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB)}));
        dkSigGen.setHashedSubpackets(PGPSignatureSubpacketVector.fromSubpackets(subpackets.toArray(new SignatureSubpacket[0])));
        PGPSignature dkSig = dkSigGen.generateCertification(primaryPublicKey);

        PGPSignatureGenerator uidSigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(primaryPublicKey.getAlgorithm(), HashAlgorithmTags.SHA512),
                primaryPublicKey);
        uidSigGen.init(PGPSignature.POSITIVE_CERTIFICATION, primaryPrivateKey);
        subpackets = new ArrayList<>();
        subpackets.add(new SignatureCreationTime(true, creationTime));
        subpackets.add(new IssuerFingerprint(false, primaryPublicKey.getVersion(), primaryPublicKey.getFingerprint()));
        uidSigGen.setHashedSubpackets(PGPSignatureSubpacketVector.fromSubpackets(subpackets.toArray(new SignatureSubpacket[0])));
        PGPSignature uidSig = uidSigGen.generateCertification(uid, primaryPublicKey);

        X448KeyPairGenerator xKpGen = new X448KeyPairGenerator();
        xKpGen.init(new X448KeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom()));
        AsymmetricCipherKeyPair xKp = xKpGen.generateKeyPair();
        PGPKeyPair xPgpKp = new BcPGPKeyPair(PublicKeyPacket.VERSION_6, PublicKeyAlgorithmTags.X448, xKp, creationTime);
        PGPPublicKey publicSubkey = xPgpKp.getPublicKey();
        PGPPrivateKey privateSubkey = xPgpKp.getPrivateKey();

        PGPSignatureGenerator subSigGen = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(primaryPublicKey.getAlgorithm(), HashAlgorithmTags.SHA3_512),
                primaryPublicKey);
        subSigGen.init(PGPSignature.SUBKEY_BINDING, primaryPrivateKey);
        subpackets = new ArrayList<>();
        subpackets.add(new IssuerFingerprint(false, primaryPublicKey.getVersion(), primaryPublicKey.getFingerprint()));
        subpackets.add(new SignatureCreationTime(true, creationTime));
        subpackets.add(new KeyFlags(true, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE));
        subSigGen.setHashedSubpackets(PGPSignatureSubpacketVector.fromSubpackets(subpackets.toArray(new SignatureSubpacket[0])));
        PGPSignature subSig = subSigGen.generateCertification(primaryPublicKey, publicSubkey);

        primaryPublicKey = PGPPublicKey.addCertification(primaryPublicKey, dkSig);
        primaryPublicKey = PGPPublicKey.addCertification(primaryPublicKey, uid, uidSig);
        publicSubkey = PGPPublicKey.addCertification(publicSubkey, subSig);

        List<PGPSecretKey> secKeys = new ArrayList<>();
        secKeys.add(new PGPSecretKey(primaryPrivateKey, primaryPublicKey,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), true, null));
        secKeys.add(new PGPSecretKey(privateSubkey, publicSubkey,
                new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1), false, null));

        PGPSecretKeyRing secretKeys = new PGPSecretKeyRing(secKeys);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
                .clearHeaders()
                .addComment(FingerprintUtil.prettifyFingerprint(primaryPublicKey.getFingerprint()))
                .addComment(FingerprintUtil.prettifyFingerprint(publicSubkey.getFingerprint()))
                .addComment(uid)
                .enableCRC(false)
                .build(bOut);
        BCPGOutputStream pOut = new BCPGOutputStream(aOut, PacketFormat.CURRENT);
        secretKeys.encode(pOut);
        pOut.close();
        aOut.close();
        System.out.println(bOut);
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPv6TestKeyGenerator());
    }
}
