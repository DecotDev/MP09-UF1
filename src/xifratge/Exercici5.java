package xifratge;

import security.utils.Xifrar;

import java.io.FileInputStream;
import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

public class Exercici5 {

    //String certificatFile;
    Xifrar xifrar;
    PublicKey publicKey;
    String ruta;

    private void setCorrectPath() throws URISyntaxException {
        //Windows 11
        //ruta = Paths.get(Exercici5.class.getResource(ruta).toURI()).toString();
        //Ubuntu 24.04.2 LTS
        ruta = Exercici5.class.getResource(ruta).getFile();
        xifrar = new Xifrar();

    }

    private void useGetPublicKey() {
        publicKey = xifrar.getCertPublicKey(ruta);

        if (publicKey != null) {
            System.out.println("Public Key Retrieved:");
            System.out.println(publicKey);
        } else {
            System.out.println("Failed to retrieve Public Key.");
        }
    }

    public Exercici5() throws URISyntaxException {
        ruta = "../mycertificate.cer";
    }

    public static void main(String[] args) throws URISyntaxException {
        Exercici5 exercici5 = new Exercici5();

        exercici5.setCorrectPath();
        exercici5.useGetPublicKey();

    }

}

/*
Terminal commands (perque no tinc res del exercici de GPG i Keytool al meu pc):
 - keytool -genkeypair -alias mycert -keyalg RSA -keysize 2048 -keystore mykeystore.jks -storepass storepassword -validity 365

C:\Users\Decot\Downloads\MP09>keytool -genkeypair -alias mycert -keyalg RSA -keysize 2048 -keystore mykeystore.jks -storepass storepassword -validity 365
Enter the distinguished name. Provide a single dot (.) to leave a sub-component empty or press ENTER to use the default value in braces.
What is your first and last name?
  [Unknown]:  David
What is the name of your organizational unit?
  [Unknown]:  DAM
What is the name of your organization?
  [Unknown]:  Puig Castellar
What is the name of your City or Locality?
  [Unknown]:  Santako
What is the name of your State or Province?
  [Unknown]:  BCN
What is the two-letter country code for this unit?
  [Unknown]:  ES
Is CN=David, OU=DAM, O=Puig Castellar, L=Santako, ST=BCN, C=ES correct?
  [no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 365 days
        for: CN=David, OU=DAM, O=Puig Castellar, L=Santako, ST=BCN, C=ES



- keytool -exportcert -alias mycert -keystore mykeystore.jks -file mycertificate.cer -storepass storepassword

C:\Users\Decot\Downloads\MP09>keytool -exportcert -alias mycert -keystore mykeystore.jks -file mycertificate.cer -storepass storepassword
Certificate stored in file <mycertificate.cer>


-keytool -printcert -file mycertificate.cer

C:\Users\Decot\Downloads\MP09>keytool -printcert -file mycertificate.cer
Owner: CN=David, OU=DAM, O=Puig Castellar, L=Santako, ST=BCN, C=ES
Issuer: CN=David, OU=DAM, O=Puig Castellar, L=Santako, ST=BCN, C=ES
Serial number: 3134ebf01b02d818
Valid from: Thu Feb 20 16:55:58 CET 2025 until: Fri Feb 20 16:55:58 CET 2026
Certificate fingerprints:
         SHA1: 55:9C:D8:40:F4:AE:11:BF:09:F5:3E:68:4B:E0:E3:67:0F:82:C8:05
         SHA256: 8A:53:02:4C:41:3F:3B:EF:16:FE:5C:90:F7:3E:9C:7F:27:15:EF:63:BB:E0:1E:E6:EA:68:7B:63:1F:F0:6F:71
Signature algorithm name: SHA384withRSA
Subject Public Key Algorithm: 2048-bit RSA key
Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 63 82 D6 4B A8 6D 0B 55   6B 43 8F 97 AB 87 B0 C8  c..K.m.UkC......
0010: B4 4E 64 EC                                        .Nd.
]
]



 */
