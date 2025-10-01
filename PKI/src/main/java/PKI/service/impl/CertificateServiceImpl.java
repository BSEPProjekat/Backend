package PKI.service.impl;

import PKI.certificates.CertificateGenerator;
import PKI.data.Certificate;
import PKI.data.Issuer;
import PKI.data.Subject;
import PKI.domain.dto.CertificateDto;
import PKI.repository.CertificateRepository;
import PKI.service.CertificateService;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Service;

import java.security.*;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

@Service
public class CertificateServiceImpl implements CertificateService {
    private final CertificateRepository certificateRepository;

    public CertificateServiceImpl(CertificateRepository certificateRepository){
        this.certificateRepository = certificateRepository;
    }

    public void issueRootCertificate(CertificateDto certificateDto){
        try{

            String alias = certificateDto.alias;
            var subject = generateSubject(certificateDto);
            var issuer = generateIssuer(certificateDto);

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
            Date startDate = sdf.parse(certificateDto.startDate);
            Date endDate = sdf.parse(certificateDto.endDate);

            String serialNumber = "1";

            X509Certificate x509Certificate = CertificateGenerator.generateCertificate(subject,
                    issuer, startDate, endDate, serialNumber);

            var certificate = new Certificate(alias, subject, issuer, serialNumber, startDate, endDate, x509Certificate);

            certificateRepository.issueRootCertificate(certificate);

        }catch (ParseException e){
            e.printStackTrace();
        }

    }

    public Subject generateSubject(CertificateDto certificateDto) {
        KeyPair keyPairSubject = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, certificateDto.commonName);
        builder.addRDN(BCStyle.SURNAME, certificateDto.surname);
        builder.addRDN(BCStyle.GIVENNAME, certificateDto.givenName);
        builder.addRDN(BCStyle.O, certificateDto.organization);
        builder.addRDN(BCStyle.OU, certificateDto.organizationalUnit);
        builder.addRDN(BCStyle.C, certificateDto.country);
        builder.addRDN(BCStyle.E, certificateDto.email);

        return new Subject(keyPairSubject.getPublic(), builder.build());
    }
    public Issuer generateIssuer(CertificateDto certificateDto) {
        KeyPair kp = generateKeyPair();

        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, certificateDto.commonName);
        builder.addRDN(BCStyle.SURNAME, certificateDto.surname);
        builder.addRDN(BCStyle.GIVENNAME, certificateDto.givenName);
        builder.addRDN(BCStyle.O, certificateDto.organization);
        builder.addRDN(BCStyle.OU, certificateDto.organizationalUnit);
        builder.addRDN(BCStyle.C, certificateDto.country);
        builder.addRDN(BCStyle.E, certificateDto.email);

        return new Issuer(kp.getPrivate(), kp.getPublic(), builder.build());
    }

    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
    public List<Certificate> getRootCertificates(){
        return certificateRepository.getRootCertificates();
    }
}