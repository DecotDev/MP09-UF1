package xifratge;

import security.utils.Xifrar;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class IntentDeGuardarKeypairAlKeystore {

    Xifrar xifrar;

    String keystoreFile; // Use PKCS12 format
    String keystorePassword;
    String keyAlias;
    String keyPassword;

    KeyStore keyStore;
    KeyPair keyPair;

    public IntentDeGuardarKeypairAlKeystore() {
        this.xifrar = new Xifrar();
    }

    private void setKeystoreStrings() {
        keystoreFile = "mykeystore.p12"; // Use PKCS12 format
        keystorePassword = "storepassword";
        keyAlias = "myRSAKey";
        keyPassword = "keypassword";
    }

    private void genKeystore() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, keystorePassword.toCharArray());
    }

    private void genKeyPair() {
        keyPair = xifrar.randomGenerate(2048);
        if (keyPair == null) {
            System.err.println("Key generation failed.");
        }
    }

    private void storeKey() throws KeyStoreException {
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),new java.security.cert.Certificate[]{});
        keyStore.setEntry(keyAlias, privateKeyEntry, entryPassword);
    }

    private void writeKeystore() {
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void printsKeystoreKeypairGeneration() {
        System.out.println("✅ Keystore (PKCS12) created successfully with an RSA key!");
        System.out.println("📌 Keystore File: " + keystoreFile);
        System.out.println("🔑 Key Alias: " + keyAlias);
        System.out.println("🛡 Public Key:\n" + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
    }

    public static void main(String[] args) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
        IntentDeGuardarKeypairAlKeystore exercici6 = new IntentDeGuardarKeypairAlKeystore();

        exercici6.setKeystoreStrings();
        exercici6.genKeystore();
        exercici6.genKeyPair();
        exercici6.storeKey();
        exercici6.writeKeystore();
        exercici6.printsKeystoreKeypairGeneration();

    }
}
