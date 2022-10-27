package Cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;

public class ClientThread extends Thread {

    private Socket socket = null;
	private int id;
	private String dlg;	
	private BigInteger p;
	private BigInteger g;
	private SecurityFunctions f;	
	private int mod;
    

    
    @Override
    public void run() {

        try {
            PrintWriter ac = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader dc = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    
}
