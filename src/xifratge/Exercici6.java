package xifratge;

import security.utils.Xifrar;

import java.net.URISyntaxException;
import java.nio.file.Paths;
import java.security.PublicKey;

public class Exercici6 {
    Xifrar xifrar;
    String ruta;

    public Exercici6() throws URISyntaxException {
        this.xifrar = new Xifrar();
        ruta = "../mykeystore.jks";
        //Windows 11
        ruta = Paths.get(Exercici5.class.getResource(ruta).toURI()).toString();
        //Ubuntu 24.04.2 LTS
        //ruta = Exercici5.class.getResource(ruta).getFile();
        xifrar = new Xifrar();
    }
}
