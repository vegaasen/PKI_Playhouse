package com.vegaasen.playhouse.utils;

import com.google.common.base.Strings;
import com.vegaasen.playhouse.types.HashType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.Key;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Simple demonstration of signing with both AES/HMac-keys and X509Certificates.
 * Based on the Sun/Oracle documentation and some demonstration located
 * <a href="http://www.java-tips.org/java-ee-tips/xml-digital-signature-api/using-the-java-xml-digital-signatur-2.html">here.</a>
 *
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public final class XmlSigningUtils {

    public static final String DEFAULT_SIGNATURE_ID = "coolSignature";

    private static final String NAMESPACE_PREFIX = "ds";
    private static final String NODE_SIGNATURE = "Signature";

    private XmlSigningUtils() {
    }

    public static void signDocumentByKey(
            final Document document,
            final String referenceId,
            String signatureId,
            final Key signingKey,
            final HashType hashType) throws SignatureException {
        if (document != null &&
                !Strings.isNullOrEmpty(referenceId) &&
                signingKey != null) {
            try {
                if (Strings.isNullOrEmpty(signatureId)) {
                    signatureId = DEFAULT_SIGNATURE_ID;
                }
                final SignedInfo signedInformation = createSignedInfo(
                        hashType.getXmlAlgorithm(),
                        new HMACParameterSpec(hashType.getBitLength()),
                        null,
                        referenceId);
                final DOMSignContext domSignContext = new DOMSignContext(signingKey, document.getDocumentElement());
                domSignContext.setDefaultNamespacePrefix(NAMESPACE_PREFIX);
                final XMLSignature signature = getXMLSignatureFactory().newXMLSignature(
                        signedInformation,
                        null,
                        null,
                        signatureId,
                        null);
                signature.sign(domSignContext);
                return;
            } catch (final Exception e) {
                throw new SignatureException("Unable to sign the document.", e);
            }
        }
        throw new IllegalArgumentException("Important argument is null, empty or missing.");
    }

    public static void signDocumentByCertificate(
            final Document document,
            final String referenceId,
            String signatureId,
            final PrivateKey privateKey,
            final X509Certificate signingCertificate
    ) throws CertificateException, SignatureException {
        if (document != null &&
                !Strings.isNullOrEmpty(referenceId) &&
                signingCertificate != null && privateKey != null) {
            if (verifyCertificateValidity(signingCertificate)) {
                try {
                    if (Strings.isNullOrEmpty(signatureId)) {
                        signatureId = DEFAULT_SIGNATURE_ID;
                    }
                    final SignedInfo signedInformation = createSignedInfo(
                            getSignatureMethodFromKey(privateKey),
                            null,
                            null,
                            referenceId
                    );
                    final KeyInfoFactory keyInfoFactory = getXMLSignatureFactory().getKeyInfoFactory();
                    final List<Object> x509Content = new ArrayList<>();
                    x509Content.add(signingCertificate.getSubjectX500Principal().getName());
                    x509Content.add(signingCertificate);

                    final X509Data certificateData = keyInfoFactory.newX509Data(x509Content);
                    final KeyInfo keyInformation = keyInfoFactory.newKeyInfo(Collections.singletonList(certificateData));
                    final DOMSignContext domSignContext = new DOMSignContext(privateKey, document.getDocumentElement());
                    domSignContext.setDefaultNamespacePrefix(NAMESPACE_PREFIX);
                    final XMLSignature signature = getXMLSignatureFactory().newXMLSignature(
                            signedInformation,
                            keyInformation,
                            null,
                            signatureId,
                            null
                    );
                    signature.sign(domSignContext);
                    return;
                } catch (Exception e) {
                    throw new SignatureException("Unable to sign the document.", e);
                }
            }
            throw new CertificateException("Certificate has expired and is not valid for signing document.");
        }
        throw new IllegalArgumentException("Important argument is null, empty or missing.");
    }

    public static boolean validateDocumentByKey(final Document document, Key validatingKey) throws SignatureException {
        final DOMValidateContext valContext =
                new DOMValidateContext(validatingKey,
                        getSignatureNode(document.getDocumentElement())
                );
        try {
            final XMLSignature signature = getXMLSignatureFactory().unmarshalXMLSignature(valContext);
            return signature.validate(valContext);
        } catch (final Exception e) {
            throw new SignatureException("Signature verification error", e);
        }
    }

    public static boolean validateDocumentByCertificate(
            final Document document,
            final X509Certificate validatingCertificate) throws CertificateException, SignatureException {
        if (verifyCertificateValidity(validatingCertificate)) {
            return validateDocumentByKey(document, validatingCertificate.getPublicKey());
        }
        return false;
    }

    private static Node getSignatureNode(final Element rootElement) throws SignatureException {
        final NodeList nl = rootElement.getElementsByTagNameNS(XMLSignature.XMLNS, NODE_SIGNATURE);
        if (nl.getLength() == 0) {
            throw new SignatureException("Cannot find Signature element");
        }
        return nl.item(0);
    }

    private static SignedInfo createSignedInfo(
            final String algorithm,
            final SignatureMethodParameterSpec methodParamSpec,
            final String signatureId,
            final String referenceUri) throws SignatureException {
        try {
            final CanonicalizationMethod canonicalizationMethod = getXMLSignatureFactory().newCanonicalizationMethod(
                    CanonicalizationMethod.EXCLUSIVE,
                    (XMLStructure) null
            );
            final SignatureMethod signatureMethod = getXMLSignatureFactory().newSignatureMethod(
                    algorithm,
                    methodParamSpec
            );
            return getXMLSignatureFactory().newSignedInfo(
                    canonicalizationMethod,
                    signatureMethod,
                    Collections.singletonList(createReference(referenceUri)),
                    signatureId
            );
        } catch (final Exception e) {
            throw new SignatureException("Error creating signed info", e);
        }
    }

    private static Reference createReference(final String uri) throws SignatureException {
        try {
            final List<Transform> transforms = new ArrayList<>();
            transforms.add(
                    getXMLSignatureFactory().newTransform(Transform.ENVELOPED,
                            (TransformParameterSpec) null));
            transforms.add(
                    getXMLSignatureFactory().newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                            (XMLStructure) null));
            final DigestMethod digestMethod = getXMLSignatureFactory().newDigestMethod(DigestMethod.SHA1, null);
            String referenceUri = "";
            if (uri != null) {
                referenceUri = uri;
            }
            return getXMLSignatureFactory().newReference(
                    referenceUri,
                    digestMethod,
                    transforms,
                    null,
                    null);
        } catch (final Exception e) {
            throw new SignatureException("Error creating reference", e);
        }
    }

    private static String getSignatureMethodFromKey(final Key key) throws SignatureException {
        switch (key.getAlgorithm()) {
            case "DSA":
                return SignatureMethod.DSA_SHA1;
            case "RSA":
                return SignatureMethod.RSA_SHA1;
            default:
                throw new SignatureException("Unknown private key algorithm `" + key.getAlgorithm() + "'.");
        }
    }

    private static boolean verifyCertificateValidity(X509Certificate certificate) throws CertificateException {
        if (certificate != null) {
            if (certificate.getNotAfter().compareTo(new Date(System.currentTimeMillis())) >= 0) {
                return true;
            }
            throw new CertificateException("Certificate has expired and is not valid for signing document.");
        }
        return false;
    }

    private static synchronized XMLSignatureFactory getXMLSignatureFactory() {
        return XMLSignatureFactory.getInstance("DOM");
    }

}
