package PKI.repository.impl;

import PKI.data.Certificate;
import PKI.data.Issuer;
import PKI.data.Subject;
import PKI.keystores.KeyStoreReader;
import PKI.keystores.KeyStoreWriter;
import PKI.repository.CertificateRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.springframework.stereotype.Repository;

import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;
import java.io.FileInputStream;

@Repository
public class CertificateRepositoryImpl implements CertificateRepository {
    private final KeyStoreReader keyStoreReader;

    private final KeyStoreWriter keyStoreWriter;
    public CertificateRepositoryImpl(){
        keyStoreReader = new KeyStoreReader();
        keyStoreWriter = new KeyStoreWriter();
    }
    public void issueRootCertificate(Certificate certificate){
        keyStoreWriter.loadKeyStore(null,  "password".toCharArray());
        keyStoreWriter.write(certificate.getAlias(), certificate.getIssuer().getPrivateKey(), "password".toCharArray(), certificate.getX509Certificate());
        keyStoreWriter.saveKeyStore("src/main/resources/keystore/" + certificate.getAlias() + ".jks", "password".toCharArray());
    }
     public List<Certificate> getRootCertificates(){
         File folder = new File("src/main/resources/keystore");
         File[] files = folder.listFiles((dir, name) -> name.endsWith(".jks"));
         if (files == null) return new ArrayList<>();

         List<Certificate> rootCertificates = new ArrayList<>();
         for (File file : files) {

             try (FileInputStream fis = new FileInputStream(file)) {
                 KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
                 keyStore.load(fis, "password".toCharArray());

                 Enumeration<String> aliases = keyStore.aliases();
                 while (aliases.hasMoreElements()) {
                     String alias = aliases.nextElement();
                     var cert = keyStore.getCertificate(alias);
                     if(cert instanceof X509Certificate){
                         X509Certificate x509 = (X509Certificate) cert;
                         Issuer issuer = keyStoreReader.readIssuer(file.getCanonicalPath(), alias, "password".toCharArray(), "password".toCharArray());
                         Subject subject = keyStoreReader.readSubject(file.getCanonicalPath(), alias, "password".toCharArray(), "password".toCharArray());
                         Certificate certificate = new Certificate(alias,
                                 subject,
                                 issuer,
                                 String.valueOf(x509.getSerialNumber()),
                                 x509.getNotBefore(),
                                 x509.getNotAfter(),
                                 x509);
                         if(certificate.getSerialNumber().equals("1"))
                             rootCertificates.add(certificate);
                     }


                 }
             }catch (Exception e){
                 e.printStackTrace();
             }
         }
         return rootCertificates;
     }

}
