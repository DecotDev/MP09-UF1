package xifratge;

import security.utils.Xifrar;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class Exercici8 {
    Xifrar xifrar;

    KeyPair keyPair;
    PrivateKey privateKey;
    PublicKey publicKey;

    String textToSing;
    byte[] signature;
    byte[] data;

    public Exercici8() {
        this.xifrar = new Xifrar();
        textToSing = "This text needs to be signed and validate its sign.";

    }

    private void genKeyPair() {
        keyPair = xifrar.randomGenerate(2048);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    private void signText() {
        data = textToSing.getBytes(StandardCharsets.UTF_8);
        signature = xifrar.signData(data, privateKey);
    }

    private void validateSignature() {
        try {
            boolean isValid = xifrar.validateSignature(data, signature, publicKey);

            System.out.println("Text signed and verified!");
            System.out.println("Original text: " + textToSing);
            System.out.println("Signature (Base64): " + java.util.Base64.getEncoder().encodeToString(signature));
            System.out.println("Signature valid: " + isValid);

        } catch (Exception e) {
            System.err.println("Error verifying signature: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Exercici8 exercici8 = new Exercici8();

        exercici8.genKeyPair();
        exercici8.signText();
        exercici8.validateSignature();
    }
}
