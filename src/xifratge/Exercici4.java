package xifratge;

import security.utils.Xifrar;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Exercici4 {

    Xifrar xifrar;

    KeyStore keyStore;
    KeyGenerator keyGenerator;
    SecretKey secretKey;

    KeyStore existingKeyStore;
    Enumeration<String> aliases;
    String aliasToCheck;
    Certificate cert;
    Key key;

    public Exercici4() {
        this.xifrar = new Xifrar();
    }

    private void createKeystore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(null, null);
    }

    private void genSecretKey() throws NoSuchAlgorithmException {
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        secretKey = keyGenerator.generateKey();
    }

    private void storeKey() throws KeyStoreException {
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection("keypassword".toCharArray());
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        keyStore.setEntry("mySecretKey", secretKeyEntry, entryPassword);
    }

    private void writeKeystore() {
        try (FileOutputStream fos = new FileOutputStream("mykeystore.jceks")) {
            keyStore.store(fos, "storepassword".toCharArray());
            System.out.println("Keystore created and key stored successfully!");
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void loadKeystore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        FileInputStream fis = new FileInputStream("mykeystore.jceks");
        existingKeyStore = KeyStore.getInstance("JCEKS");
        existingKeyStore.load(fis, "storepassword".toCharArray()); // Keystore password
        fis.close();
        System.out.println("Keystore Type: " + existingKeyStore.getType());
    }

    private void keystoreSize() throws KeyStoreException {
        aliases = existingKeyStore.aliases();
        int keyCount = 0;
        while (aliases.hasMoreElements()) {
            aliases.nextElement();
            keyCount++;
        }
        System.out.println("Keystore Size (Number of Keys): " + keyCount);
    }

    private void printAlias() throws KeyStoreException {
        System.out.println("Stored Keys:");
        aliases = existingKeyStore.aliases(); // Reset enumeration
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println(" - Alias: " + alias);
        }
    }

    private void printCert() throws KeyStoreException {
        aliasToCheck = "mySecretKey"; // Change this if needed
        if (existingKeyStore.containsAlias(aliasToCheck)) {
            cert = existingKeyStore.getCertificate(aliasToCheck);
            if (cert != null) {
                System.out.println("Certificate for alias '" + aliasToCheck + "':");
                System.out.println(cert.toString());
            } else {
                System.out.println("No certificate found for alias '" + aliasToCheck + "'");
            }
        } else {
            System.out.println("Alias '" + aliasToCheck + "' not found in Keystore.");
        }
    }

    private void printAlgo() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        key = existingKeyStore.getKey(aliasToCheck, "keypassword".toCharArray());
        if (key instanceof SecretKey) {
            System.out.println("Cipher Algorithm of Key '" + aliasToCheck + "': " + key.getAlgorithm());
        } else {
            System.out.println("The key '" + aliasToCheck + "' is not a SecretKey.");
        }
    }



    public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Exercici4 exercici4 = new Exercici4();

        exercici4.createKeystore();
        exercici4.genSecretKey();
        exercici4.storeKey();
        exercici4.writeKeystore();

        exercici4.loadKeystore();
        exercici4.keystoreSize();
        exercici4.printAlias();
        exercici4.printCert();
        exercici4.printAlgo();

    }
}
