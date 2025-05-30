package org.bouncycastle.tsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Store;

/**
 * Carrier class for a TimeStampToken.
 */
public class TimeStampToken
{
    CMSSignedData tsToken;

    SignerInformation tsaSignerInfo;

    TimeStampTokenInfo tstInfo;
    
    ESSCertIDv2 certID;

    public TimeStampToken(ContentInfo contentInfo)
        throws TSPException, IOException
    {
        this(getSignedData(contentInfo));
    }

    private static CMSSignedData getSignedData(ContentInfo contentInfo)
        throws TSPException
    {
        try
        {
            return new CMSSignedData(contentInfo);
        }
        catch (CMSException e)
        {
            throw new TSPException("TSP parsing error: " + e.getMessage(), e.getCause());
        }
    }

    public TimeStampToken(CMSSignedData signedData)
        throws TSPException, IOException
    {
        this.tsToken = signedData;

        if (!this.tsToken.getSignedContentTypeOID().equals(PKCSObjectIdentifiers.id_ct_TSTInfo.getId()))
        {
            throw new TSPValidationException("ContentInfo object not for a time stamp.");
        }

        Collection<SignerInformation> signers = tsToken.getSignerInfos().getSigners();

        if (signers.size() != 1)
        {
            throw new IllegalArgumentException("Time-stamp token signed by "
                    + signers.size()
                    + " signers, but it must contain just the TSA signature.");
        }

        tsaSignerInfo = (SignerInformation)signers.iterator().next();

        try
        {
            CMSProcessable content = tsToken.getSignedContent();
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            content.write(bOut);

            this.tstInfo = new TimeStampTokenInfo(TSTInfo.getInstance(bOut.toByteArray()));

            Attribute attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate);

            if (attr != null)
            {
                SigningCertificate signCert = SigningCertificate.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = ESSCertIDv2.from(ESSCertID.getInstance(signCert.getCerts()[0]));
            }
            else
            {
                attr = tsaSignerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);

                if (attr == null)
                {
                    throw new TSPValidationException("no signing certificate attribute found, time stamp invalid.");
                }

                SigningCertificateV2 signCertV2 = SigningCertificateV2.getInstance(attr.getAttrValues().getObjectAt(0));

                this.certID = ESSCertIDv2.getInstance(signCertV2.getCerts()[0]);
            }
        }
        catch (CMSException e)
        {
            throw new TSPException(e.getMessage(), e.getUnderlyingException());
        }
    }

    public TimeStampTokenInfo getTimeStampInfo()
    {
        return tstInfo;
    }

    public SignerId getSID()
    {
        return tsaSignerInfo.getSID();
    }
    
    public AttributeTable getSignedAttributes()
    {
        return tsaSignerInfo.getSignedAttributes();
    }

    public AttributeTable getUnsignedAttributes()
    {
        return tsaSignerInfo.getUnsignedAttributes();
    }

    public Store<X509CertificateHolder> getCertificates()
    {
        return tsToken.getCertificates();
    }

    public Store<X509CRLHolder> getCRLs()
    {
        return tsToken.getCRLs();
    }

    public Store<X509AttributeCertificateHolder> getAttributeCertificates()
    {
        return tsToken.getAttributeCertificates();
    }

    /**
     * Validate the time stamp token.
     * <p>
     * To be valid the token must be signed by the passed in certificate and
     * the certificate must be the one referred to by the SigningCertificate
     * attribute included in the hashed attributes of the token. The
     * certificate must also have the ExtendedKeyUsageExtension with only
     * KeyPurposeId.id_kp_timeStamping and have been valid at the time the
     * timestamp was created.
     * </p>
     * <p>
     * A successful call to validate means all the above are true.
     * </p>
     *
     * @param sigVerifier the content verifier create the objects required to verify the CMS object in the timestamp.
     * @throws TSPException if an exception occurs in processing the token.
     * @throws TSPValidationException if the certificate or signature fail to be valid.
     * @throws IllegalArgumentException if the sigVerifierProvider has no associated certificate.
     */
    public void validate(
        SignerInformationVerifier sigVerifier)
        throws TSPException, TSPValidationException
    {
        if (!sigVerifier.hasAssociatedCertificate())
        {
            throw new IllegalArgumentException("verifier provider needs an associated certificate");
        }

        try
        {
            X509CertificateHolder certHolder = sigVerifier.getAssociatedCertificate();
            DigestCalculator calc = sigVerifier.getDigestCalculator(certID.getHashAlgorithm());

            OutputStream cOut = calc.getOutputStream();
            cOut.write(certHolder.getEncoded());
            cOut.close();

            if (!Arrays.constantTimeAreEqual(certID.getCertHashObject().getOctets(), calc.getDigest()))
            {
                throw new TSPValidationException("certificate hash does not match certID hash.");
            }

            IssuerSerial issuerSerial = certID.getIssuerSerial();
            if (issuerSerial != null)
            {
                Certificate c = certHolder.toASN1Structure();

                if (!issuerSerial.getSerial().equals(c.getSerialNumber()))
                {
                    throw new TSPValidationException("certificate serial number does not match certID for signature.");
                }

                GeneralName[] names = issuerSerial.getIssuer().getNames();
                boolean found = false;

                for (int i = 0; i != names.length; i++)
                {
                    if (names[i].getTagNo() == GeneralName.directoryName &&
                        X500Name.getInstance(names[i].getName()).equals(c.getIssuer()))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    throw new TSPValidationException("certificate name does not match certID for signature. ");
                }
            }

            TSPUtil.validateCertificate(certHolder);

            if (!certHolder.isValidOn(tstInfo.getGenTime()))
            {
                throw new TSPValidationException("certificate not valid when time stamp created.");
            }

            if (!tsaSignerInfo.verify(sigVerifier))
            {
                throw new TSPValidationException("signature not created by certificate.");
            }
        }
        catch (CMSException e)
        {
            if (e.getUnderlyingException() != null)
            {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
            else
            {
                throw new TSPException("CMS exception: " + e, e);
            }
        }
        catch (IOException e)
        {
            throw new TSPException("problem processing certificate: " + e, e);
        }
        catch (OperatorCreationException e)
        {
            throw new TSPException("unable to create digest: " + e.getMessage(), e);
        }
    }

    /**
     * Return true if the signature on time stamp token is valid.
     * <p>
     * Note: this is a much weaker proof of correctness than calling validate().
     * </p>
     *
     * @param sigVerifier the content verifier create the objects required to verify the CMS object in the timestamp.
     * @return true if the signature matches, false otherwise.
     * @throws TSPException if the signature cannot be processed or the provider cannot match the algorithm.
     */
    public boolean isSignatureValid(
        SignerInformationVerifier sigVerifier)
        throws TSPException
    {
        try
        {
            return tsaSignerInfo.verify(sigVerifier);
        }
        catch (CMSException e)
        {
            if (e.getUnderlyingException() != null)
            {
                throw new TSPException(e.getMessage(), e.getUnderlyingException());
            }
            else
            {
                throw new TSPException("CMS exception: " + e, e);
            }
        }
    }

    /**
     * Return the underlying CMSSignedData object.
     * 
     * @return the underlying CMS structure.
     */
    public CMSSignedData toCMSSignedData()
    {
        return tsToken;
    }
    
    /**
     * Return a ASN.1 encoded byte stream representing the encoded object.
     * 
     * @throws IOException if encoding fails.
     */
    public byte[] getEncoded() 
        throws IOException
    {
        return tsToken.getEncoded(ASN1Encoding.DL);
    }

    /**
     * return the ASN.1 encoded representation of this object using the specified encoding.
     *
     * @param encoding the ASN.1 encoding format to use ("BER", "DL", or "DER").
     */
    public byte[] getEncoded(String encoding)
        throws IOException
    {
        return tsToken.getEncoded(encoding);
    }
}
