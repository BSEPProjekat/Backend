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
import java.io.FileOutputStream;
import java.math.BigInteger;
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
     public List<Certificate> getCertificates(){
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
                         rootCertificates.add(certificate);
                     }


                 }
             }catch (Exception e){
                 e.printStackTrace();
             }
         }
         return rootCertificates;
     }

     public Issuer getIssuer(BigInteger serialNumber){
         File folder = new File("src/main/resources/keystore");
         File[] files = folder.listFiles((dir, name) -> name.endsWith(".jks"));

         for (File file : files) {

             try (FileInputStream fis = new FileInputStream(file)) {
                 KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
                 keyStore.load(fis, "password".toCharArray());


                 Enumeration<String> aliases = keyStore.aliases();
                 while (aliases.hasMoreElements()) {
                     String alias = aliases.nextElement();
                     var cert = keyStore.getCertificate(alias);
                     if(cert instanceof X509Certificate x509){
                         if(serialNumber.equals(x509.getSerialNumber())){
                            return keyStoreReader.readIssuerForNextCertificate(file.getCanonicalPath(), alias, "password".toCharArray(), "password".toCharArray());
                         }
                     }


                 }
             }catch (Exception e){
                 e.printStackTrace();
             }

         }
         return null;
     }

    public void issueCertificate(Certificate certificate, BigInteger serialNumber) {
        File folder = new File("src/main/resources/keystore");
        File[] files = folder.listFiles((dir, name) -> name.endsWith(".jks"));

        if (files == null) {
            System.err.println("No keystore files found in " + folder.getAbsolutePath());
            return;
        }

        for (File file : files) {
            try (FileInputStream fis = new FileInputStream(file)) {
                KeyStore keyStore = KeyStore.getInstance("JKS", "SUN");
                keyStore.load(fis, "password".toCharArray());

                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    java.security.cert.Certificate cert = keyStore.getCertificate(alias);

                    if (cert instanceof X509Certificate x509) {
                        if (serialNumber.equals(x509.getSerialNumber()) && keyStore.isKeyEntry(alias)) {
                            System.out.println("Issuer alias: " + alias);

                            java.security.cert.Certificate[] oldChain = keyStore.getCertificateChain(alias);

                            java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[oldChain.length + 1];
                            newChain[0] = certificate.getX509Certificate();
                            System.arraycopy(oldChain, 0, newChain, 1, oldChain.length);

                            keyStore.setKeyEntry(
                                    certificate.getAlias(),
                                    certificate.getIssuer().getPrivateKey(),
                                    "password".toCharArray(),
                                    newChain
                            );
                            try (FileOutputStream fos = new FileOutputStream(file)) {
                                keyStore.store(fos, "password".toCharArray());
                            }

                            System.out.println("Certificate " + certificate.getAlias() + " successfully issued and added to keystore: " + file.getName());
                            return;
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
