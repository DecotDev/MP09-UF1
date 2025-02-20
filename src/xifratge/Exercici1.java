package xifratge;

import security.utils.Xifrar;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Exercici1 {
    Xifrar xifrar;

    public Exercici1() {
        xifrar = new Xifrar();
    }


    public void exercici1_5() throws UnsupportedEncodingException, BadPaddingException {
        System.out.println("* Inici exercici 1.5 *");
        SecretKey key = xifrar.keygenKeyGeneration(128);
        String text = "Això és un missatget secret";
        //String textXifrat = new String (xifrar.encryptData(key, text.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        byte[] textXifrat = xifrar.encryptData(key, text.getBytes());
        //System.out.println("Text xifrat: " + textXifrat);
        String textXifratString = new String(textXifrat);
        System.out.println("Text xifrat: " + textXifratString);
        //String textDesxifrat = new String(xifrar.decryptData(key, textXifrat.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        String textDesxifrat = new String(xifrar.decryptData(key, textXifrat), StandardCharsets.UTF_8);
        //String textDesxifrat = new String(xifrar.decryptData(key, stringXifrat.getBytes()));

        System.out.println("Text desxifrat: " + textDesxifrat + "\n");
    }

    public void exercici1_6() throws BadPaddingException {
        System.out.println("* Inici exercici 1.6 *");
        SecretKey key = xifrar.passwordKeyGeneration("secret", 128);
        String text = "Missatge xifrat amb clau secreta >:3";
        byte[] textXifrat = xifrar.encryptData(key, text.getBytes(StandardCharsets.UTF_8));
        String textXifratString = new String(textXifrat);
        System.out.println("Text xifrat: " + textXifratString);
        String textDesxifrat = new String(xifrar.decryptData(key, textXifrat), StandardCharsets.UTF_8);
        System.out.println("Text desxifrat: " + textDesxifrat + "\n");
    }

    public void exercici1_7() {
        System.out.println("* Inici exercici 1.7 *");
        SecretKey secretKey = xifrar.keygenKeyGeneration(128);
        System.out.println("Algoritme: " + secretKey.getAlgorithm());
        System.out.println("Format: " + secretKey.getFormat());
        System.out.println("Class: " + secretKey.getClass());
        System.out.println("Encoded: " + Arrays.toString(secretKey.getEncoded()));
        System.out.println("Hash code: " + secretKey.hashCode());
        System.out.println("To string: " + secretKey.toString());
        System.out.println("Is destroyed?: " + secretKey.isDestroyed());
        //System.out.println("Destruïm la clau.");
        //secretKey.destroy();
        //System.out.println("Is destroyed?: " + secretKey.isDestroyed());
        //secretKey.wait(400);
    }
    public void exercici1_8() {
        System.out.println("* Inici exercici 1.8 *");
        System.out.println("Xifrem com al 1.6:");
        SecretKey key1 = xifrar.passwordKeyGeneration("secret", 128);
        String text = "Missatge xifrat amb clau secreta >:3";
        byte[] textXifrat = xifrar.encryptData(key1, text.getBytes(StandardCharsets.UTF_8));
        String textXifratString = new String(textXifrat);
        System.out.println("Text xifrat: " + textXifratString);
        System.out.println("Creem una clau amb una paraula de pas incorrecta:");
        SecretKey key2 = xifrar.passwordKeyGeneration("malaClau", 128);
        try {
            String textDesxifrat = new String(xifrar.decryptData(key2, textXifrat), StandardCharsets.UTF_8);
            System.out.println("Text desxifrat: " + textDesxifrat + "\n");
        } catch (BadPaddingException e) {
            System.out.println("Error de BadPaddingException.");
        }
    }

    public static void main(String[] args) throws UnsupportedEncodingException, BadPaddingException {
        Exercici1 exercici1 = new Exercici1();
        exercici1.exercici1_5();
        exercici1.exercici1_6();
        exercici1.exercici1_7();
        exercici1.exercici1_8();
    }
}


/*
De String a bytes: msg.getBytes(“UTF8”);
De bytes a String: new String(textenbytes,”UTF8”);
Classes que podeu usar:
	Path path = Paths.get(“ruta del arxiu”);
	byte[] textenbytes = Files.readAllBytes(path);
Altres:
File, BufferedReader, FileReader

 */