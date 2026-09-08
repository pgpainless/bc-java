package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;

import java.security.PublicKey;
import java.util.Date;

/**
 * An OpenPGP key stored on a {@link OpenPGPSmartCard}.
 */
public class OpenPGPHardwareKey
{
    /**
     * Key used to generate signatures.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#SIGN_DATA}.
     */
    public static final byte KEY_REF_SIGNATURE = 1;

    /**
     * Key used to decrypt messages.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#ENCRYPT_COMMS} and
     * {@link org.bouncycastle.bcpg.sig.KeyFlags#ENCRYPT_STORAGE}.
     */
    public static final byte KEY_REF_DECRYPTION = 2;

    /**
     * Key used for authentication.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#AUTHENTICATION}.
     */
    public static final byte KEY_REF_AUTHENTICATION = 3;

    /**
     * Key was generated on the device itself.
     */
    public static final byte STATE_GENERATED = 1;

    /**
     * Key was generated somewhere else and was imported onto the device.
     * A copy of the private key MAY exist somewhere else.
     */
    public static final byte STATE_IMPORTED = 2;

    private final OpenPGPSmartCard smartCard;
    private final byte keyRef;
    private final byte[] fingerprint;
    private final Date generationTime;
    private final byte state;

    public OpenPGPHardwareKey(OpenPGPSmartCard smartCard,
                              byte keyRef,
                              byte state,
                              byte[] fingerprint,
                              Date generationTime)
    {
        this.smartCard = smartCard;
        this.keyRef = keyRef;
        // defensive copies: this is the card key's identity and creation metadata, and a caller that
        // kept a reference to either array/Date could otherwise mutate it after construction
        this.fingerprint = Arrays.clone(fingerprint);
        this.generationTime = generationTime == null ? null : new Date(generationTime.getTime());
        this.state = state;
    }

    /**
     * Return the contents of the fingerprint field.
     * Note: The fingerprint field of OpenPGP smart cards is a 20-octet field that can contain arbitrary
     * data.
     * Since the smart card does not make use of this field and does not validate its contents, you MUST NOT
     * rely on this field to identify keys.
     * Notably OpenPGP v6 keys, which have a 32-octet fingerprint, will cause mismatches with the 20-octet field.
     *
     * @return content of fingerprint field
     */
    public byte[] getFingerprint()
    {
        return Arrays.clone(fingerprint);
    }

    /**
     * Retrieve the full OpenPGP key fingerprint by reconstructing the
     * {@link org.bouncycastle.openpgp.PGPPublicKey} and retrieving its fingerprint.
     *
     * @return full fingerprint
     * @throws PGPException if the key cannot be reconstructed
     * @throws CardException if communication with the card fails
     */
    public byte[] reconstructFullFingerprint()
            throws PGPException, CardException
    {
        return getSmartCard().reconstructPGPPublicKey(getKeyRef())
                .getFingerprint();
    }

    /**
     * Return the {@link KeyIdentifier} based on the reconstructed full key fingerprint.
     *
     * @return key identifier
     * @throws PGPException if the key cannot be reconstructed
     * @throws CardException if communication with the card fails
     */
    public KeyIdentifier getFullKeyIdentifier()
            throws PGPException, CardException
    {
        return new KeyIdentifier(reconstructFullFingerprint());
    }

    /**
     * Return the creation time of the key.
     * @return creation time
     */
    public Date getCreationTime()
    {
        return generationTime == null ? null : new Date(generationTime.getTime());
    }

    /**
     * Return the key reference (keyRef) of this key.
     *
     * @return key ref
     */
    public byte getKeyRef()
    {
        return keyRef;
    }

    /**
     * Return the {@link OpenPGPSmartCard} this key is stored on.
     *
     * @return smart card
     */
    public OpenPGPSmartCard getSmartCard()
    {
        return smartCard;
    }

    /**
     * Return true if the key has been imported onto the device.
     * Note: A copy of the private key MAY still exist somewhere else.
     *
     * @return true if key was imported
     */
    public boolean isImported()
    {
        return state == STATE_IMPORTED;
    }

    /**
     * Return true if the key was generated on/by the device itself.
     *
     * @return true if key was generated
     */
    public boolean isGenerated()
    {
        return state == STATE_GENERATED;
    }

    /**
     * Perform a public-key signing operation over the given <pre>digest</pre> using this hardware key.
     * Note: The resulting signature is a raw cryptographic signature and needs to be framed into an OpenPGP signature
     * packet.
     *
     * @param userPinProvider provider for the PIN of this key
     * @param stubKey stubbed OpenPGPSecretKey corresponding to this hardware key.
     * @param digest encoded message digest
     * @return raw cryptographic signature
     */
    public byte[] sign(KeyPassphraseProvider userPinProvider, OpenPGPKey.OpenPGPSecretKey stubKey, byte[] digest)
            throws PGPException, CardException
    {
        return getSmartCard().sign(digest, this, stubKey, userPinProvider);
    }

    /**
     * Perform a public-key decryption operation over the given ciphertext using this hardware key.
     * Note: The <pre>message</pre> ciphertext is not an OpenPGP message, but represents the algorithm-specific
     * encrypted session-key data as specified in RFC9580.
     * This method is used with RSA and ElGamal keys.
     *
     * @param userPinProvider provider for this keys user PIN
     * @param stubKey stubbed OpenPGPSecretKey corresponding to this hardware key.
     * @param message algorithm-specific encrypted session key data
     * @return decrypted algorithm-specific session key data
     */
    public byte[] decrypt(KeyPassphraseProvider userPinProvider,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          byte[] message)
            throws CardException, KeyPassphraseException
    {
        return getSmartCard().decrypt(message, this, stubKey, userPinProvider);
    }

    /**
     * Perform a public-key handshake to establish a shared secret using this hardware key.
     * Note: The <pre>ephemeralKey</pre> represents an algorithm-specific ephemeral key used to encrypt/decrypt
     * a message session key.
     * This method is used with ECDH, X25519, X448 keys.
     *
     * @param userPinProvider provider for this keys user PIN
     * @param stubKey stubbed OpenPGPSecretKey corresponding to this hardware key.
     * @param ephemeralKey algorithm-specific ephemeral message public key
     * @return decrypted algorithm-specific session key data
     */
    public byte[] decrypt(KeyPassphraseProvider userPinProvider,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          PublicKey ephemeralKey)
            throws CardException, KeyPassphraseException
    {
        return getSmartCard().decrypt(ephemeralKey, this, stubKey, userPinProvider);
    }
}
