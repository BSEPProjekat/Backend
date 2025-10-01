package PKI.controller;

import PKI.data.Certificate;
import PKI.domain.dto.CertificateDto;
import PKI.service.CertificateService;
import jakarta.validation.Valid;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@RestController
public class CertificateController {
    private final CertificateService certificateService;

    public CertificateController(CertificateService certificateService){
        this.certificateService = certificateService;
    }

    @PostMapping("/issueRootCertificate")
    public ResponseEntity<String> issueCertificate(@Valid @RequestBody CertificateDto certificateDto) {
        certificateService.issueRootCertificate(certificateDto);
        return ResponseEntity.status(HttpStatus.CREATED).body("Certificate issued successfully");
    }

    @GetMapping("/getRootCertificates")
    public ResponseEntity<List<CertificateDto>> getRootCertificates() {
        List<Certificate> rootCertificates = certificateService.getRootCertificates();
        List<CertificateDto> rootCertificateDtos = new ArrayList<>();

        for (Certificate cert : rootCertificates) {
            rootCertificateDtos.add(mapToDto(cert));
        }

        return ResponseEntity.ok(rootCertificateDtos);
    }

    private CertificateDto mapToDto(Certificate cert) {
        CertificateDto dto = new CertificateDto();

        X509Certificate x509 = cert.getX509Certificate();

        try {
            X500Name x500name = new JcaX509CertificateHolder(x509).getSubject();

            for (RDN rdn : x500name.getRDNs()) {
                AttributeTypeAndValue atv = rdn.getFirst();
                if (atv == null) continue;

                ASN1ObjectIdentifier type = atv.getType();
                String value = atv.getValue().toString();

                if (type.equals(BCStyle.CN)) {
                    dto.commonName = value;
                } else if (type.equals(BCStyle.SURNAME)) {
                    dto.surname = value;
                } else if (type.equals(BCStyle.GIVENNAME)) {
                    dto.givenName = value;
                } else if (type.equals(BCStyle.O)) {
                    dto.organization = value;
                } else if (type.equals(BCStyle.OU)) {
                    dto.organizationalUnit = value;
                } else if (type.equals(BCStyle.C)) {
                    dto.country = value;
                } else if (type.equals(BCStyle.EmailAddress)) {
                    dto.email = value;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        dto.alias = cert.getAlias();
        dto.startDate = String.valueOf(x509.getNotBefore().getTime());
        dto.endDate = String.valueOf(x509.getNotAfter().getTime());
        dto.publicKey = Base64.getEncoder().encodeToString(x509.getPublicKey().getEncoded());

        return dto;
    }




}
