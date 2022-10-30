package Cliente;

/*
    Used SecurityFunctions.java from Server source code
 */

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
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

    public SecretKey csk1(String semilla) throws Exception {
        // * create secret key 1, semilla = master key
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded1 = new byte[32];
        for(int i = 0; i < 32 ; i++) {
            encoded1[i] = encodedhash[i];
        }
        SecretKey sk = null;
        sk = new SecretKeySpec(encoded1,"AES");
        return sk;
    }

    public SecretKey csk2(String semilla) throws Exception {
        // * create secret key 2, semilla = master key (this is the key used for MAC)
        byte[] byte_semilla = semilla.trim().getBytes(StandardCharsets.UTF_8);
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] encodedhash = digest.digest(byte_semilla);
        byte[] encoded2 = new byte[32];
        for (int i = 32; i < 64 ; i++) {
            encoded2[i-32] = encodedhash[i];
        }
        SecretKey sk = null;
        sk = new SecretKeySpec(encoded2,"AES");
        return sk;
    }
    
}
