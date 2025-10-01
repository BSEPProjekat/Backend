package PKI.service;

import PKI.data.Certificate;
import PKI.domain.dto.CertificateDto;

import java.util.List;

public interface CertificateService {
    public void issueRootCertificate(CertificateDto certificateDto);
    public List<Certificate> getRootCertificates();
}
