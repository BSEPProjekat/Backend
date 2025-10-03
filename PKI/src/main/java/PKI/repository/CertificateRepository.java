package PKI.repository;

import PKI.data.Certificate;
import PKI.data.Issuer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.math.BigInteger;
import java.util.List;

public interface CertificateRepository {
    public void issueRootCertificate(Certificate certificate);
    public List<Certificate> getCertificates();
    public Issuer getIssuer(BigInteger serialNumber);
    public void issueCertificate(Certificate certificate, BigInteger serialNumber);
}
