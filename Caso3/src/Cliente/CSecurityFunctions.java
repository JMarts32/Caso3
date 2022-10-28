package Cliente;

/*
    Used SecurityFunctions.java from Server source code
 */

import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

public class CSecurityFunctions {

    public boolean checkSignature(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        // * @Cliente Verifica F(K_w-, (G, P, G^x)) usando la llave publica del servidor K_w+
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publica);
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        boolean isCorrect = publicSignature.verify(firma);
        return isCorrect;
    }

    public PublicKey read_kplus(String fileName, String id) {
        FileInputStream is1;
        PublicKey pubkey = null;
        System.out.println(id+fileName);
        try {
            is1 = new FileInputStream(fileName);
            File f = new File(fileName);
            byte[] inBytes1 = new byte[(int)f.length()];
            is1.read(inBytes1);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(inBytes1);
            pubkey = kf.generatePublic(publicKeySpec);
            is1.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubkey;
    }
    
}
