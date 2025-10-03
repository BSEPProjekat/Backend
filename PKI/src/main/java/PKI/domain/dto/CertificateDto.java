package PKI.domain.dto;

import java.security.PublicKey;

public class CertificateDto {
    public String alias;
    public String commonName;
    public String surname;
    public String givenName;
    public String organization;
    public String organizationalUnit;
    public String country;
    public String email;
    public String startDate;
    public String endDate;
    public String publicKey;
    public String serialNumber;
    public CertificateDto(){}
}