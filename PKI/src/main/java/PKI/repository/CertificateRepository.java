package PKI.repository;

import PKI.data.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CertificateRepository {
    public void issueRootCertificate(Certificate certificate);
    public List<Certificate> getRootCertificates();
}
