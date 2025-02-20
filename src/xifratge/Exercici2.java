package xifratge;

import security.utils.Xifrar;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Exercici2 {

    Xifrar xifrar;

    List<String> passwords;
    File pswdFile;
    Path encryptedFilePath;
    Scanner sc;

    String ruta;
    String ruta2;

    String decryptedText;

    public Exercici2() throws FileNotFoundException, URISyntaxException {
        this.xifrar = new Xifrar();

        //Windows 11
        //this.ruta = Paths.get(Exercici2.class.getResource("../clausA4.txt").toURI()).toString();
        //this.ruta2 = Paths.get(Exercici2.class.getResource("../textamagat.crypt").toURI()).toString();

        //Ubuntu 24.04.2 LTS
        this.ruta = Exercici2.class.getResource("../clausA4.txt").getFile();
        this.ruta2 = Exercici2.class.getResource("../textamagat.crypt").getFile();


        this.passwords = new ArrayList<>();
        this.encryptedFilePath = Paths.get(ruta2);
        this.pswdFile = new File(ruta);
        this.sc = new Scanner(pswdFile);



    }

    public void readPswds() {
        while (sc.hasNextLine()) {
            passwords.add(sc.nextLine());

        }
    }

    public void tryPswd(String password) throws IOException, BadPaddingException {
        SecretKey key = xifrar.passwordKeyGeneration(password,128);
        byte[] textBytesFormat = Files.readAllBytes(encryptedFilePath);
        //if (decryptedText != null) return;
        try {
            decryptedText = new String(xifrar.decryptData(key, textBytesFormat), StandardCharsets.UTF_8);
            System.out.println("Decrypted text: " + decryptedText);
            System.out.println("Password: " + password);
        } catch (BadPaddingException e) {
        }
    }


    public static void main(String[] args) throws IOException, BadPaddingException, URISyntaxException {
        Exercici2 exercici2 = new Exercici2();

        exercici2.readPswds();
        for (String password : exercici2.passwords) {
            exercici2.tryPswd(password);
            //System.out.println(exercici2.decryptedText);
        }
        //System.out.println(exercici2.decryptedText);


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
