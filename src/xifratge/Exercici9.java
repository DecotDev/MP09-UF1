package xifratge;

import security.utils.Xifrar;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Exercici9 {
    Xifrar xifrar;

    KeyPair keyPair;
    PublicKey publicKey;
    PrivateKey privateKey;

    String textToEncrypt;
    byte[] data;
    byte[][] encryptedData;

    public Exercici9() {
        xifrar = new Xifrar();
        textToEncrypt = "Text secret que hem de xifrar i desxifrar :3";
    }

    private void genKeys(){
        keyPair = xifrar.randomGenerate(2048);
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    private void encryptText() {
        data = textToEncrypt.getBytes(StandardCharsets.UTF_8);

        encryptedData = xifrar.encryptWrappedData(data, publicKey);
        System.out.println("Encrypted text: " + new String(encryptedData[0], StandardCharsets.UTF_8));
        System.out.println("Encrypted AES Key: " + new String(encryptedData[1], StandardCharsets.UTF_8));
    }

    private void decryptText() {
        try {
            byte[] decryptedData = xifrar.decryptWrappedData(encryptedData, privateKey);
            System.out.println("Decrypted Message: " + new String(decryptedData, StandardCharsets.UTF_8));
        } catch (Exception e) {
            System.err.println("Error during encryption/decryption: " + e);
        }
    }

    public static void main(String[] args) {
        Exercici9 exercici9 = new Exercici9();

        exercici9.genKeys();
        exercici9.encryptText();
        exercici9.decryptText();
    }
}
