package xifratge;

import security.utils.Xifrar;

import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PublicKey;

public class Exercici6 {
    Xifrar xifrar;
    String ruta;

    String keystorePassword;
    String keyAlias;
    String keyPassword;

    KeyStore keyStore;
    PublicKey publicKey;

    public Exercici6() throws URISyntaxException {
        this.xifrar = new Xifrar();
        ruta = "../mykeystore.p12";
        //Windows 11
        ruta = Paths.get(Exercici5.class.getResource(ruta).toURI()).toString();
        //Ubuntu 24.04.2 LTS
        //ruta = Exercici5.class.getResource(ruta).getFile();
        xifrar = new Xifrar();
    }

    private void setKeystoreStrings() {

        keystorePassword = "storepassword";
        keyAlias = "myKeyAlias";
        keyPassword = "keypassword";
    }

    private void loadKeystore() throws Exception {
        keyStore = xifrar.loadKeyStore(ruta, keystorePassword);
    }

    private void getAndPrintPublicKey() {
        publicKey = Xifrar.getPublicKey(keyStore, keyAlias, keyPassword);
        if (publicKey != null) {
            System.out.println("Public key loaded successfully!");
            System.out.println("Public key: " + publicKey);
        } else {
            System.err.println("Failed to load a public key from the keystore.");
        }
    }

    public static void main(String[] args) throws Exception {
        Exercici6 exercici6 = new Exercici6();

        exercici6.setKeystoreStrings();
        exercici6.loadKeystore();
        exercici6.getAndPrintPublicKey();
    }

}
