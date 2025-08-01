package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGObject;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ECSecretBCPGKey;
import org.bouncycastle.bcpg.Ed25519SecretBCPGKey;
import org.bouncycastle.bcpg.Ed448SecretBCPGKey;
import org.bouncycastle.bcpg.EdSecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicKeyUtils;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.bcpg.X25519SecretBCPGKey;
import org.bouncycastle.bcpg.X448SecretBCPGKey;
import org.bouncycastle.gpg.SExprParser;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * general class to handle and construct  a PGP secret key object.
 */
public class PGPSecretKey
{
    SecretKeyPacket secret;
    PGPPublicKey pub;

    public PGPSecretKey(
        SecretKeyPacket secret,
        PGPPublicKey pub)
    {
        this.secret = secret;
        this.pub = pub;
    }

    PGPSecretKey(
        PGPPrivateKey privKey,
        PGPPublicKey pubKey,
        PGPDigestCalculator checksumCalculator,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        this(privKey, pubKey, checksumCalculator, false, keyEncryptor);
    }

    /**
     * Construct a PGPSecretKey using the passed in private key and public key. This constructor will not add any
     * certifications but assumes that pubKey already has what is required.
     *
     * @param privKey            the private key component.
     * @param pubKey             the public key component.
     * @param checksumCalculator a calculator for the private key checksum
     * @param isMasterKey        true if the key is a master key, false otherwise.
     * @param keyEncryptor       an encryptor for the key if required (null otherwise).
     * @throws PGPException if there is an issue creating the secret key packet.
     */
    public PGPSecretKey(
        PGPPrivateKey privKey,
        PGPPublicKey pubKey,
        PGPDigestCalculator checksumCalculator,
        boolean isMasterKey,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        this.pub = buildPublicKey(isMasterKey, pubKey);
        this.secret = buildSecretKeyPacket(isMasterKey, privKey, pubKey, keyEncryptor, checksumCalculator);
    }

    private static PGPPublicKey buildPublicKey(boolean isMasterKey, PGPPublicKey pubKey)
    {
        PublicKeyPacket pubPacket = pubKey.publicPk;

        // make sure we can actually do what's wanted
        if (isMasterKey && !(pubKey.isEncryptionKey() && pubPacket.getAlgorithm() != PublicKeyAlgorithmTags.RSA_GENERAL))
        {
            PGPPublicKey mstKey = new PGPPublicKey(pubKey);
            mstKey.publicPk = new PublicKeyPacket(pubPacket.getVersion(), pubPacket.getAlgorithm(), pubPacket.getTime(), pubPacket.getKey());
            return mstKey;
        }
        else
        {
            PGPPublicKey subKey = new PGPPublicKey(pubKey);
            subKey.publicPk = new PublicSubkeyPacket(pubPacket.getVersion(), pubPacket.getAlgorithm(), pubPacket.getTime(), pubPacket.getKey());
            return subKey;
        }
    }

    private static SecretKeyPacket buildSecretKeyPacket(boolean isMasterKey, PGPPrivateKey privKey, PGPPublicKey pubKey, PBESecretKeyEncryptor keyEncryptor, PGPDigestCalculator checksumCalculator)
        throws PGPException
    {
        BCPGObject secKey = (BCPGObject)privKey.getPrivateKeyDataPacket();

        if (secKey == null)
        {
            return generateSecretKeyPacket(isMasterKey, pubKey.publicPk, SymmetricKeyAlgorithmTags.NULL, new byte[0]);
        }

        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            BCPGOutputStream pOut = new BCPGOutputStream(bOut);

            pOut.writeObject(secKey);

            byte[] keyData = bOut.toByteArray();

            int encAlgorithm = (keyEncryptor != null) ? keyEncryptor.getAlgorithm() : SymmetricKeyAlgorithmTags.NULL;

            if (encAlgorithm != SymmetricKeyAlgorithmTags.NULL)
            {
                pOut.write(checksum(checksumCalculator, keyData, keyData.length));

                keyData = bOut.toByteArray(); // include checksum

                byte[] encData = keyEncryptor.encryptKeyData(keyData, 0, keyData.length);
                byte[] iv = keyEncryptor.getCipherIV();

                S2K s2k = keyEncryptor.getS2K();

                int s2kUsage;
                if (keyEncryptor.getAeadAlgorithm() != 0)
                {
                    s2kUsage = SecretKeyPacket.USAGE_AEAD;
                    return generateSecretKeyPacket(isMasterKey, pubKey.publicPk, encAlgorithm, keyEncryptor.getAeadAlgorithm(), s2kUsage, s2k, iv, encData);
                }

                if (checksumCalculator != null)
                {
                    if (checksumCalculator.getAlgorithm() != HashAlgorithmTags.SHA1)
                    {
                        throw new PGPException("only SHA1 supported for key checksum calculations.");
                    }
                    s2kUsage = SecretKeyPacket.USAGE_SHA1;
                }
                else
                {
                    s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
                }

                return generateSecretKeyPacket(isMasterKey, pubKey.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
            }
            else if (pubKey.getVersion() != PublicKeyPacket.VERSION_6)
            {
                pOut.write(checksum(null, keyData, keyData.length));
            }
            return generateSecretKeyPacket(isMasterKey, pubKey.publicPk, encAlgorithm, bOut.toByteArray());
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception encrypting key", e);
        }
    }

    private static SecretKeyPacket generateSecretKeyPacket(boolean isMasterKey, PublicKeyPacket pubKey, int encAlgorithm, byte[] secKeyData)
    {
        if (isMasterKey)
        {
            return new SecretKeyPacket(pubKey, encAlgorithm, null, null, secKeyData);
        }
        else
        {
            return new SecretSubkeyPacket(pubKey, encAlgorithm, null, null, secKeyData);
        }
    }

    private static SecretKeyPacket generateSecretKeyPacket(boolean isMasterKey, PublicKeyPacket pubKey, int encAlgorithm, int s2kusage, S2K s2k, byte[] iv, byte[] secKeyData)
    {
        if (isMasterKey)
        {
            return new SecretKeyPacket(pubKey, encAlgorithm, s2kusage, s2k, iv, secKeyData);
        }
        else
        {
            return new SecretSubkeyPacket(pubKey, encAlgorithm, s2kusage, s2k, iv, secKeyData);
        }
    }

    private static SecretKeyPacket generateSecretKeyPacket(boolean isMasterKey, PublicKeyPacket pubKey, int encAlgorithm, int aeadAlgorithm, int s2kUsage, S2K s2K, byte[] iv, byte[] secKeyData)
    {
        if (isMasterKey)
        {
            return new SecretKeyPacket(pubKey, encAlgorithm, aeadAlgorithm, s2kUsage, s2K, iv, secKeyData);
        }
        else
        {
            return new SecretSubkeyPacket(pubKey, encAlgorithm, aeadAlgorithm, s2kUsage, s2K, iv, secKeyData);
        }
    }

    /**
     * Construct a PGPSecretKey using the passed in private/public key pair and binding it to the passed in id
     * using a generated certification of certificationLevel.The secret key checksum is calculated using the original
     * non-digest based checksum.
     *
     * @param certificationLevel         the type of certification to be added.
     * @param keyPair                    the public/private keys to use.
     * @param id                         the id to bind to the key.
     * @param hashedPcks                 the hashed packets to be added to the certification.
     * @param unhashedPcks               the unhashed packets to be added to the certification.
     * @param certificationSignerBuilder the builder for generating the certification.
     * @param keyEncryptor               an encryptor for the key if required (null otherwise).
     * @throws PGPException if there is an issue creating the secret key packet or the certification.
     */
    public PGPSecretKey(
        int certificationLevel,
        PGPKeyPair keyPair,
        String id,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        PGPContentSignerBuilder certificationSignerBuilder,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        this(certificationLevel, keyPair, id, null, hashedPcks, unhashedPcks, certificationSignerBuilder, keyEncryptor);
    }

    /**
     * Construct a PGPSecretKey sub-key using the passed in private/public key pair and binding it to the master key pair.
     * The secret key checksum is calculated using the passed in checksum calculator.
     *
     * @param masterKeyPair              the master public/private keys for the new subkey.
     * @param keyPair                    the public/private keys to use.
     * @param checksumCalculator         a calculator for the private key checksum
     * @param certificationSignerBuilder the builder for generating the certification.
     * @param keyEncryptor               an encryptor for the key if required (null otherwise).
     * @throws PGPException if there is an issue creating the secret key packet or the certification.
     */
    public PGPSecretKey(
        PGPKeyPair masterKeyPair,
        PGPKeyPair keyPair,
        PGPDigestCalculator checksumCalculator,
        PGPContentSignerBuilder certificationSignerBuilder,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        this(masterKeyPair, keyPair, checksumCalculator, null, null, certificationSignerBuilder, keyEncryptor);
    }

    /**
     * Construct a PGPSecretKey sub-key using the passed in private/public key pair and binding it to the master key pair.
     * The secret key checksum is calculated using the passed in checksum calculator.
     *
     * @param masterKeyPair              the master public/private keys for the new subkey.
     * @param keyPair                    the public/private keys to use.
     * @param checksumCalculator         calculator for PGP key checksums.
     * @param hashedPcks                 the hashed packets to be added to the certification.
     * @param unhashedPcks               the unhashed packets to be added to the certification.
     * @param certificationSignerBuilder the builder for generating the certification.
     * @param keyEncryptor               an encryptor for the key if required (null otherwise).
     * @throws PGPException if there is an issue creating the secret key packet or the certification.
     */
    public PGPSecretKey(
        PGPKeyPair masterKeyPair,
        PGPKeyPair keyPair,
        PGPDigestCalculator checksumCalculator,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        PGPContentSignerBuilder certificationSignerBuilder,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        //
        // generate the certification
        //
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(certificationSignerBuilder);

        sGen.init(PGPSignature.SUBKEY_BINDING, masterKeyPair.getPrivateKey());

        // do some basic checking if we are a signing key.
        if (!keyPair.getPublicKey().isEncryptionKey())
        {
            if (hashedPcks == null)
            {
                PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(certificationSignerBuilder);

                signatureGenerator.init(PGPSignature.PRIMARYKEY_BINDING, keyPair.getPrivateKey());

                PGPSignatureSubpacketGenerator subGen = new PGPSignatureSubpacketGenerator();

                try
                {
                    subGen.addEmbeddedSignature(false, signatureGenerator.generateCertification(masterKeyPair.getPublicKey(), keyPair.getPublicKey()));

                    hashedPcks = subGen.generate();
                }
                catch (IOException e)
                {
                    throw new PGPException(e.getMessage(), e);
                }
            }
            else if (!hashedPcks.hasSubpacket(SignatureSubpacketTags.EMBEDDED_SIGNATURE))
            {
                throw new PGPException("signing subkey requires embedded PRIMARYKEY_BINDING signature");
            }
        }

        sGen.setHashedSubpackets(hashedPcks);
        sGen.setUnhashedSubpackets(unhashedPcks);

        List<PGPSignature> subSigs = new ArrayList<PGPSignature>();

        subSigs.add(sGen.generateCertification(masterKeyPair.getPublicKey(), keyPair.getPublicKey()));

        // replace the public key packet structure with a public subkey one.
        PGPPublicKey pubSubKey = new PGPPublicKey(keyPair.getPublicKey(), null, subSigs);

        pubSubKey.publicPk = new PublicSubkeyPacket(pubSubKey.getVersion(), pubSubKey.getAlgorithm(), pubSubKey.getCreationTime(), pubSubKey.publicPk.getKey());

        this.pub = pubSubKey;
        this.secret = buildSecretKeyPacket(false, keyPair.getPrivateKey(), keyPair.getPublicKey(), keyEncryptor, checksumCalculator);
    }

    /**
     * Construct a PGPSecretKey using the passed in private/public key pair and binding it to the passed in id
     * using a generated certification of certificationLevel.
     *
     * @param certificationLevel         the type of certification to be added.
     * @param keyPair                    the public/private keys to use.
     * @param id                         the id to bind to the key.
     * @param checksumCalculator         a calculator for the private key checksum.
     * @param hashedPcks                 the hashed packets to be added to the certification.
     * @param unhashedPcks               the unhashed packets to be added to the certification.
     * @param certificationSignerBuilder the builder for generating the certification.
     * @param keyEncryptor               an encryptor for the key if required (null otherwise).
     * @throws PGPException if there is an issue creating the secret key packet or the certification.
     */
    public PGPSecretKey(
        int certificationLevel,
        PGPKeyPair keyPair,
        String id,
        PGPDigestCalculator checksumCalculator,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        PGPContentSignerBuilder certificationSignerBuilder,
        PBESecretKeyEncryptor keyEncryptor)
        throws PGPException
    {
        this(keyPair.getPrivateKey(), certifiedPublicKey(certificationLevel, keyPair, id, hashedPcks, unhashedPcks, certificationSignerBuilder), checksumCalculator, true, keyEncryptor);
    }

    private static PGPPublicKey certifiedPublicKey(
        int certificationLevel,
        PGPKeyPair keyPair,
        String id,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        PGPContentSignerBuilder certificationSignerBuilder)
        throws PGPException
    {
        PGPSignatureGenerator sGen;

        try
        {
            sGen = new PGPSignatureGenerator(certificationSignerBuilder);
        }
        catch (Exception e)
        {
            throw new PGPException("creating signature generator: " + e, e);
        }

        //
        // generate the certification
        //
        sGen.init(certificationLevel, keyPair.getPrivateKey());

        sGen.setHashedSubpackets(hashedPcks);
        sGen.setUnhashedSubpackets(unhashedPcks);

        try
        {
            PGPSignature certification = sGen.generateCertification(id, keyPair.getPublicKey());

            return PGPPublicKey.addCertification(keyPair.getPublicKey(), id, certification);
        }
        catch (Exception e)
        {
            throw new PGPException("exception doing certification: " + e, e);
        }
    }

    /**
     * Return true if this key has an algorithm type that makes it suitable to use for signing.
     * <p>
     * Note: with version 4 keys KeyFlags subpackets should also be considered when present for
     * determining the preferred use of the key.
     *
     * @return true if this key algorithm is suitable for use with signing.
     */
    public boolean isSigningKey()
    {
        return PublicKeyUtils.isSigningAlgorithm(pub.getAlgorithm());
    }

    /**
     * Return true if this is a master key.
     *
     * @return true if a master key.
     */
    public boolean isMasterKey()
    {
        return pub.isMasterKey();
    }

    /**
     * Detect if the Secret Key's Private Key is empty or not
     *
     * @return boolean whether or not the private key is empty
     */
    public boolean isPrivateKeyEmpty()
    {
        byte[] secKeyData = secret.getSecretKeyData();

        return (secKeyData == null || secKeyData.length < 1);
    }

    /**
     * return the algorithm the key is encrypted with.
     *
     * @return the algorithm used to encrypt the secret key.
     */
    public int getKeyEncryptionAlgorithm()
    {
        return secret.getEncAlgorithm();
    }

    /**
     * Return the AEAD algorithm the key is encrypted with.
     * Returns <pre>0</pre> if no AEAD is used.
     *
     * @return aead key encryption algorithm
     */
    public int getAEADKeyEncryptionAlgorithm()
    {
        return secret.getAeadAlgorithm();
    }

    /**
     * Return the keyID of the public key associated with this key.
     *
     * @return the keyID associated with this key.
     */
    public long getKeyID()
    {
        return pub.getKeyID();
    }

    /**
     * Return a {@link KeyIdentifier} for this key.
     *
     * @return identifier
     */
    public KeyIdentifier getKeyIdentifier()
    {
        return this.getPublicKey().getKeyIdentifier();
    }

    /**
     * Return the fingerprint of the public key associated with this key.
     *
     * @return key fingerprint.
     */
    public byte[] getFingerprint()
    {
        return pub.getFingerprint();
    }

    /**
     * Return the S2K usage associated with this key.
     * This value indicates, how the secret key material is protected:
     * <ul>
     *     <li>{@link SecretKeyPacket#USAGE_NONE}: Unprotected</li>
     *     <li>{@link SecretKeyPacket#USAGE_CHECKSUM}: Password-protected using malleable CFB (deprecated)</li>
     *     <li>{@link SecretKeyPacket#USAGE_SHA1}: Password-protected using CFB</li>
     *     <li>{@link SecretKeyPacket#USAGE_AEAD}: Password-protected using AEAD (recommended)</li>
     * </ul>
     *
     * @return the key's S2K usage
     */
    public int getS2KUsage()
    {
        return secret.getS2KUsage();
    }

    /**
     * Return the S2K used to process this key
     *
     * @return the key's S2K, null if one is not present.
     */
    public S2K getS2K()
    {
        return secret.getS2K();
    }

    /**
     * Return the public key associated with this key.
     *
     * @return the public key for this key.
     */
    public PGPPublicKey getPublicKey()
    {
        return pub;
    }

    /**
     * Return any userIDs associated with the key.
     *
     * @return an iterator of Strings.
     */
    public Iterator<String> getUserIDs()
    {
        return pub.getUserIDs();
    }

    /**
     * Return any user attribute vectors associated with the key.
     *
     * @return an iterator of PGPUserAttributeSubpacketVector.
     */
    public Iterator<PGPUserAttributeSubpacketVector> getUserAttributes()
    {
        return pub.getUserAttributes();
    }

    private byte[] extractKeyData(PBESecretKeyDecryptor decryptorFactory) throws PGPException
    {
        byte[] encData = secret.getSecretKeyData();

        if (secret.getEncAlgorithm() == SymmetricKeyAlgorithmTags.NULL)
        {
            return encData;
        }

        try
        {
            byte[] key = decryptorFactory.makeKeyFromPassPhrase(secret.getEncAlgorithm(), secret.getS2K());
            byte[] data;

            if (secret.getPublicKeyPacket().getVersion() >= PublicKeyPacket.VERSION_4)
            {
                if (secret.getS2KUsage() == SecretKeyPacket.USAGE_AEAD)
                {
                    // privKey := AEAD(HKDF(S2K(passphrase), info), secrets, packetprefix)
                    return decryptorFactory.recoverKeyData(
                        secret.getEncAlgorithm(),
                        secret.getAeadAlgorithm(),
                        key, // s2k output = ikm for hkdf
                        secret.getIV(), // iv = aead nonce
                        secret.getPacketTag(),
                        secret.getPublicKeyPacket().getVersion(),
                        secret.getSecretKeyData(),
                        secret.getPublicKeyPacket().getEncodedContents());
                }
                else
                {
                    data = decryptorFactory.recoverKeyData(secret.getEncAlgorithm(), key, secret.getIV(), encData, 0, encData.length);

                    boolean useSHA1 = secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1;
                    byte[] check = checksum(useSHA1 ? decryptorFactory.getChecksumCalculator(HashAlgorithmTags.SHA1) : null, data, (useSHA1) ? data.length - 20 : data.length - 2);

                    if (!Arrays.constantTimeAreEqual(check.length, check, 0, data, data.length - check.length))
                    {
                        throw new PGPException("checksum mismatch in checksum of " + check.length + " bytes");
                    }
                }
            }
            else // version 2 or 3, RSA only.
            {

                data = new byte[encData.length];

                byte[] iv = new byte[secret.getIV().length];

                System.arraycopy(secret.getIV(), 0, iv, 0, iv.length);

                //
                // read in the four numbers
                //
                int pos = 0;

                for (int i = 0; i != 4; i++)
                {
                    int encLen = ((((encData[pos] & 0xff) << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                    data[pos] = encData[pos];
                    data[pos + 1] = encData[pos + 1];

                    if (encLen > (encData.length - (pos + 2)))
                    {
                        throw new PGPException("out of range encLen found in encData");
                    }
                    byte[] tmp = decryptorFactory.recoverKeyData(secret.getEncAlgorithm(), key, iv, encData, pos + 2, encLen);
                    System.arraycopy(tmp, 0, data, pos + 2, tmp.length);
                    pos += 2 + encLen;

                    if (i != 3)
                    {
                        System.arraycopy(encData, pos - iv.length, iv, 0, iv.length);
                    }
                }

                //
                // verify and copy checksum
                //

                data[pos] = encData[pos];
                data[pos + 1] = encData[pos + 1];

                int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                int calcCs = 0;
                for (int j = 0; j < data.length - 2; j++)
                {
                    calcCs += data[j] & 0xff;
                }

                calcCs &= 0xffff;
                if (calcCs != cs)
                {
                    throw new PGPException("checksum mismatch: passphrase wrong, expected "
                        + Integer.toHexString(cs)
                        + " found " + Integer.toHexString(calcCs));
                }
            }

            return data;
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception decrypting key", e);
        }
    }

    /**
     * Extract a PGPPrivate key from the SecretKey's encrypted contents.
     *
     * @param decryptorFactory factory to use to generate a decryptor for the passed in secretKey.
     * @return PGPPrivateKey  the unencrypted private key.
     * @throws PGPException on failure.
     */
    public PGPKeyPair extractKeyPair(
        PBESecretKeyDecryptor decryptorFactory)
        throws PGPException
    {
        return new PGPKeyPair(this.getPublicKey(), this.extractPrivateKey(decryptorFactory));
    }

    /**
     * Extract a PGPPrivate key from the SecretKey's encrypted contents.
     *
     * @param decryptorFactory factory to use to generate a decryptor for the passed in secretKey.
     * @return PGPPrivateKey  the unencrypted private key.
     * @throws PGPException on failure.
     */
    public PGPPrivateKey extractPrivateKey(
        PBESecretKeyDecryptor decryptorFactory)
        throws PGPException
    {
        if (isPrivateKeyEmpty())
        {
            return null;
        }

        PublicKeyPacket pubPk = secret.getPublicKeyPacket();

        try
        {
            byte[] data = extractKeyData(decryptorFactory);
            BCPGInputStream in = new BCPGInputStream(new ByteArrayInputStream(data));


            switch (pubPk.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
            case PGPPublicKey.RSA_SIGN:
                RSASecretBCPGKey rsaPriv = new RSASecretBCPGKey(in);

                return new PGPPrivateKey(this.getKeyID(), pubPk, rsaPriv);
            case PGPPublicKey.DSA:
                DSASecretBCPGKey dsaPriv = new DSASecretBCPGKey(in);

                return new PGPPrivateKey(this.getKeyID(), pubPk, dsaPriv);
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                ElGamalSecretBCPGKey elPriv = new ElGamalSecretBCPGKey(in);

                return new PGPPrivateKey(this.getKeyID(), pubPk, elPriv);
            case PGPPublicKey.ECDH:
            case PGPPublicKey.ECDSA:
                ECSecretBCPGKey ecPriv = new ECSecretBCPGKey(in);
                return new PGPPrivateKey(this.getKeyID(), pubPk, ecPriv);
            case PGPPublicKey.X25519:
                return new PGPPrivateKey(this.getKeyID(), pubPk, new X25519SecretBCPGKey(in));
            case PGPPublicKey.X448:
                return new PGPPrivateKey(this.getKeyID(), pubPk, new X448SecretBCPGKey(in));
            case PGPPublicKey.EDDSA_LEGACY:
                return new PGPPrivateKey(this.getKeyID(), pubPk, new EdSecretBCPGKey(in));
            case PGPPublicKey.Ed25519:
                return new PGPPrivateKey(this.getKeyID(), pubPk, new Ed25519SecretBCPGKey(in));
            case PGPPublicKey.Ed448:
                return new PGPPrivateKey(this.getKeyID(), pubPk, new Ed448SecretBCPGKey(in));
            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
    }

    private static byte[] checksum(PGPDigestCalculator digCalc, byte[] bytes, int length)
        throws PGPException
    {
        if (digCalc != null)
        {
            OutputStream dOut = digCalc.getOutputStream();

            try
            {
                dOut.write(bytes, 0, length);

                dOut.close();
            }
            catch (Exception e)
            {
                throw new PGPException("checksum digest calculation failed: " + e.getMessage(), e);
            }
            return digCalc.getDigest();
        }
        else
        {
            int checksum = 0;

            for (int i = 0; i != length; i++)
            {
                checksum += bytes[i] & 0xff;
            }

            byte[] check = new byte[2];

            check[0] = (byte)(checksum >> 8);
            check[1] = (byte)checksum;

            return check;
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut);

        return bOut.toByteArray();
    }

    public void encode(OutputStream outStream)
        throws IOException
    {
        BCPGOutputStream out = BCPGOutputStream.wrap(outStream);

        out.writePacket(secret);
        if (pub.trustPk != null)
        {
            out.writePacket(pub.trustPk);
        }

        if (pub.subSigs == null)        // is not a sub key
        {
            Util.encodePGPSignatures(out, pub.keySigs, false);

            for (int i = 0; i != pub.ids.size(); i++)
            {
                if (pub.ids.get(i) instanceof UserIDPacket)
                {
                    UserIDPacket id = (UserIDPacket)pub.ids.get(i);

                    out.writePacket(id);
                }
                else
                {
                    PGPUserAttributeSubpacketVector v = (PGPUserAttributeSubpacketVector)pub.ids.get(i);

                    out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
                }

                if (pub.idTrusts.get(i) != null)
                {
                    out.writePacket((TrustPacket)pub.idTrusts.get(i));
                }

                List<PGPSignature> sigs = (List<PGPSignature>)pub.idSigs.get(i);
                Util.encodePGPSignatures(out, sigs, false);
            }
        }
        else
        {
            Util.encodePGPSignatures(out, pub.subSigs, false);
        }

        // For clarity; really only required if using partial body lengths
        out.finish();
    }

    /**
     * Return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key             the PGPSecretKey to be copied.
     * @param oldKeyDecryptor the current decryptor based on the current password for key.
     * @param newKeyEncryptor a new encryptor based on a new password for encrypting the secret key material.
     */
    public static PGPSecretKey copyWithNewPassword(
        PGPSecretKey key,
        PBESecretKeyDecryptor oldKeyDecryptor,
        PBESecretKeyEncryptor newKeyEncryptor)
        throws PGPException
    {
        return copyWithNewPassword(key, oldKeyDecryptor, newKeyEncryptor, null);
    }

    /**
     * Return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key                the PGPSecretKey to be copied.
     * @param oldKeyDecryptor    the current decryptor based on the current password for key.
     * @param newKeyEncryptor    a new encryptor based on a new password for encrypting the secret key material.
     * @param checksumCalculator digest based checksum calculator for private key data.
     */
    public static PGPSecretKey copyWithNewPassword(
        PGPSecretKey key,
        PBESecretKeyDecryptor oldKeyDecryptor,
        PBESecretKeyEncryptor newKeyEncryptor,
        PGPDigestCalculator checksumCalculator)
        throws PGPException
    {
        if (key.isPrivateKeyEmpty())
        {
            throw new PGPException("no private key in this SecretKey - public key present only.");
        }

        byte[] rawKeyData = key.extractKeyData(oldKeyDecryptor);
        int s2kUsage = key.secret.getS2KUsage();
        byte[] iv = null;
        S2K s2k = null;
        byte[] keyData;
        int newEncAlgorithm = SymmetricKeyAlgorithmTags.NULL;

        if (newKeyEncryptor == null || newKeyEncryptor.getAlgorithm() == SymmetricKeyAlgorithmTags.NULL)
        {
            s2kUsage = SecretKeyPacket.USAGE_NONE;
            if (key.secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1)   // SHA-1 hash, need to rewrite checksum
            {
                keyData = new byte[rawKeyData.length - 18];

                System.arraycopy(rawKeyData, 0, keyData, 0, keyData.length - 2);

                byte[] check = checksum(null, keyData, keyData.length - 2);

                keyData[keyData.length - 2] = check[0];
                keyData[keyData.length - 1] = check[1];
            }
            else
            {
                keyData = rawKeyData;
            }
        }
        else
        {
            if (key.secret.getPublicKeyPacket().getVersion() < 4)
            {
                if (s2kUsage == SecretKeyPacket.USAGE_NONE)
                {
                    s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
                }
                // Version 2 or 3 - RSA Keys only

                byte[] encKey = newKeyEncryptor.getKey();
                keyData = new byte[rawKeyData.length];

                if (newKeyEncryptor.getHashAlgorithm() != HashAlgorithmTags.MD5)
                {
                    throw new PGPException("MD5 Digest Calculator required for version 3 key encryptor.");
                }

                //
                // process 4 numbers
                //
                int pos = 0;
                for (int i = 0; i != 4; i++)
                {
                    int encLen = ((((rawKeyData[pos] & 0xff) << 8) | (rawKeyData[pos + 1] & 0xff)) + 7) / 8;

                    keyData[pos] = rawKeyData[pos];
                    keyData[pos + 1] = rawKeyData[pos + 1];

                    if (encLen > (rawKeyData.length - (pos + 2)))
                    {
                        throw new PGPException("out of range encLen found in rawKeyData");
                    }

                    byte[] tmp;
                    if (i == 0)
                    {
                        tmp = newKeyEncryptor.encryptKeyData(encKey, rawKeyData, pos + 2, encLen);
                        iv = newKeyEncryptor.getCipherIV();

                    }
                    else
                    {
                        byte[] tmpIv = new byte[iv.length];

                        System.arraycopy(keyData, pos - iv.length, tmpIv, 0, tmpIv.length);
                        tmp = newKeyEncryptor.encryptKeyData(encKey, tmpIv, rawKeyData, pos + 2, encLen);
                    }

                    System.arraycopy(tmp, 0, keyData, pos + 2, tmp.length);
                    pos += 2 + encLen;
                }

                //
                // copy in checksum.
                //
                keyData[pos] = rawKeyData[pos];
                keyData[pos + 1] = rawKeyData[pos + 1];

            }
            else
            {
                if (s2kUsage == SecretKeyPacket.USAGE_NONE)
                {
                    if (checksumCalculator != null)
                    {
                        if (checksumCalculator.getAlgorithm() != HashAlgorithmTags.SHA1)
                        {
                            throw new IllegalArgumentException("only SHA-1 supported for checksums");
                        }
                        s2kUsage = SecretKeyPacket.USAGE_SHA1;

                        byte[] check = checksum(checksumCalculator, rawKeyData, rawKeyData.length);
                        rawKeyData = Arrays.concatenate(rawKeyData, check);
                    }
                    else
                    {
                        s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
                    }
                }
                keyData = newKeyEncryptor.encryptKeyData(rawKeyData, 0, rawKeyData.length);

                iv = newKeyEncryptor.getCipherIV();

            }
            s2k = newKeyEncryptor.getS2K();
            newEncAlgorithm = newKeyEncryptor.getAlgorithm();
        }

        SecretKeyPacket secret;

        if (newKeyEncryptor!= null && newKeyEncryptor.getAeadAlgorithm() > 0)
        {
            s2kUsage = SecretKeyPacket.USAGE_AEAD;
            secret = generateSecretKeyPacket(!(key.secret instanceof SecretSubkeyPacket), key.secret.getPublicKeyPacket(), newEncAlgorithm, newKeyEncryptor.getAeadAlgorithm(), s2kUsage, s2k, iv, keyData);
        }
        else
        {
            secret = generateSecretKeyPacket(!(key.secret instanceof SecretSubkeyPacket), key.secret.getPublicKeyPacket(), newEncAlgorithm, s2kUsage, s2k, iv, keyData);
        }

        return new PGPSecretKey(secret, key.pub);
    }

    /**
     * Replace the passed the public key on the passed in secret key.
     *
     * @param secretKey secret key to change
     * @param publicKey new public key.
     * @return a new secret key.
     * @throws IllegalArgumentException if keyIDs do not match.
     */
    public static PGPSecretKey replacePublicKey(PGPSecretKey secretKey, PGPPublicKey publicKey)
    {
        if (publicKey.getKeyID() != secretKey.getKeyID())
        {
            throw new IllegalArgumentException("keyIDs do not match");
        }

        return new PGPSecretKey(secretKey.secret, publicKey);
    }

    /**
     * Parse a secret key from one of the GPG S expression keys associating it with the passed in public key.
     *
     * @return a secret key object.
     * @deprecated use org.bouncycastle.gpg.SExprParser - it will also allow you to verify the protection checksum if it is available.
     */
    public static PGPSecretKey parseSecretKeyFromSExpr(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, PGPPublicKey pubKey)
        throws IOException, PGPException
    {
        return new SExprParser(null).parseSecretKey(inputStream, keyProtectionRemoverFactory, pubKey);
    }

    /**
     * Parse a secret key from one of the GPG S expression keys.
     *
     * @return a secret key object.
     * @deprecated use org.bouncycastle.gpg.SExprParser - it will also allow you to verify the protection checksum if it is available.
     */
    public static PGPSecretKey parseSecretKeyFromSExpr(InputStream inputStream, PBEProtectionRemoverFactory keyProtectionRemoverFactory, KeyFingerPrintCalculator fingerPrintCalculator)
        throws IOException, PGPException
    {
        return new SExprParser(null).parseSecretKey(inputStream, keyProtectionRemoverFactory, fingerPrintCalculator);
    }
}
