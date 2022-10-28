package Cliente;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

public class ClientThread extends Thread {

    private Socket socket;
    private PrintWriter as;
    private BufferedReader ds;
    private BufferedReader stdIn;
	private int id;
	private BigInteger p;
	private BigInteger g;
	private CSecurityFunctions cF;


    public ClientThread(Socket socket, PrintWriter as, BufferedReader ds, BufferedReader stdIn) {
        this.socket = socket;
        this.as = as;
        this.ds = ds;
        this.stdIn = stdIn;
        this.id = ThreadLocalRandom.current().nextInt(0, 256);
    }

    @Override
    public void run() {

        boolean success = true;
        String line;
        System.out.println(id + " starting.");
        cF = new CSecurityFunctions();

        try {

            // * Step 0a: Read server's public key (K_W+)
            PublicKey publicKey = cF.read_kplus("datos_asim_srv.pub", String.valueOf(this.id));

            // * Step 0b: Generate private y value
            SecureRandom r = new SecureRandom();
            int y = Math.abs(r.nextInt());

            Long longY = Long.valueOf(y);
            BigInteger biy = BigInteger.valueOf(longY);

            // TODO: this too?
//            BigInteger valor_comun = G2X(g,bix,p);
//            String str_valor_comun = valor_comun.toString();
//            System.out.println(dlg + "G2X: "+str_valor_comun);

            // * Step 1: Client requests secure connection with server
            as.println("SECURE INIT");

            // * Step 3. Client recieves G, P, G^x and verifies the signature

            // G
            line = ds.readLine();
            g = new BigInteger(line);

            // P
            line = ds.readLine();
            p = new BigInteger(line);

            // G^x
            line = ds.readLine();
            BigInteger g2x = new BigInteger(line);

            // Signature
            line = ds.readLine();
            byte[] byte_auth = str2byte(line);

            // * Step 4: Verifiy F(K_W-, (G, P, G^x))
            // g.toString()+","+p.toString()+","+str_valor_comun;
            // TODO: revisar str_valor_comun
            String msg = g.toString()+","+p.toString()+","+g2x;
            boolean result = cF.checkSignature(publicKey, byte_auth, msg);


           // * Step 5: Send result of signature verification
            if (result) {
                // Send OK to server
                as.println("OK");
                System.out.println("G, P, G^x and the signature F(K_W-, (G, P, G^x)) were recieved and verified");
                // PRINT message to usr
            } else {
                // Send ERROR to server
                as.println("ERROR");
            }

            // * Step 6a: Generate G^y

            // * Step 6b: Send G^y

            // * Step 7a: Master key, Symm Key for encryption (K_AB1), Symm Key for HMAC (K_AB2), gen IV1


            int request = ThreadLocalRandom.current().nextInt(100);
            // * Step 8a: Send encrypted request C(K_AB1, <consulta>)

            // * Step 8a: send HMAC(K_AB, <consulta>)

            // * Step 8a: send iv1

            // * Step 10: Recieve responde from server
            line = ds.readLine();
            if(line.compareTo("ERROR") == 0) {
                //
            } else if (line.compareTo("OK") == 0) {
                // * Step 11a: Recive C(K_AB1, <rta>

                // * Step 11b: Recive HMAC(K_AB1, <rta>

                // * Step 11c: Recive iv2

                // * Step 12a: Verify C(K_AB1, <rta>) and  HMAC(K_AB1, <rta>

                // send OK | ERROR according to verification results 
            } else {

            }


        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }


    /*
    Methods from Servidor/SecurityFunctions
     */

    public byte[] str2byte( String ss)
    {
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length()/2];
        for (int i = 0 ; i < ret.length ; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
        }
        return ret;
    }

    public String byte2str( byte[] b )
    {
        // Encapsulamiento con hexadecimales
        String ret = "";
        for (int i = 0 ; i < b.length ; i++) {
            String g = Integer.toHexString(((char)b[i])&0x00ff);
            ret += (g.length()==1?"0":"") + g;
        }
        return ret;
    }
    
}
