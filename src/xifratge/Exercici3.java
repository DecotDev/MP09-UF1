package xifratge;

import security.utils.Xifrar;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Exercici3 {

    Scanner sc = new Scanner(System.in);

    Xifrar xifrar;
    KeyPair keyPair;

    PublicKey publicKey;
    PrivateKey privateKey;

    String textToEncrypt;
    byte[] encryptedText;
    String decryptedText;

    public Exercici3() {
        this.xifrar = new Xifrar();
    }

    private void genKeyPair() {
        keyPair = xifrar.randomGenerate(2048);
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    private void readTextToEncrypt() {
        System.out.print("Quin text vols xifrar: ");
        textToEncrypt = sc.nextLine();
    }

    private void encyptText() throws Exception {
        encryptedText = xifrar.encryptWithPublicKey(publicKey, textToEncrypt.getBytes());
    }

    private void decryptText() throws Exception {
        decryptedText = new String(xifrar.decryptWithPrivateKey(privateKey, encryptedText));
    }

    private void printsDelExercici() throws UnsupportedEncodingException {
        String xifratTemporal = new String(encryptedText, StandardCharsets.UTF_8);
        System.out.println("Text xifrat: ");
        System.out.println(xifratTemporal);
        System.out.println("Text desxifrat: " + decryptedText);
    }

    public static void main(String[] args) throws Exception {
        Exercici3 exercici3 = new Exercici3();

        exercici3.genKeyPair();
        exercici3.readTextToEncrypt();
        exercici3.encyptText();
        exercici3.decryptText();

        exercici3.printsDelExercici();

    }
}
