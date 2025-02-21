package xifratge;

import security.utils.Xifrar;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class Exercici7 {
    Xifrar xifrar;

    KeyPair keyPair;
    PrivateKey privateKey;
    PublicKey publicKey;

    String textToSign;

    public Exercici7() {
        xifrar = new Xifrar();
        textToSign = "Ojala estigues signat OwO";
    }

    private void genKeyPair(){
        keyPair = xifrar.randomGenerate(2048);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    private void signText() {
        try {
            byte[] data = textToSign.getBytes(StandardCharsets.UTF_8);

            byte[] signature = xifrar.signData(data, privateKey);

            System.out.println("Text signed successfully!");
            System.out.println("Original text: " + textToSign);
            System.out.println("Signature (Base64): " + java.util.Base64.getEncoder().encodeToString(signature));

        } catch (Exception e) {
            System.err.println("Error signing text: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Exercici7 exercici7 = new Exercici7();

        exercici7.genKeyPair();
        exercici7.signText();
    }
}
