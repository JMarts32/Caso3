package Cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClienteMain {

    private static final int PORT = 4030; 
    private static final String HOST = "localhoåst";

    public static void main(String[] args) {

        Socket socket = null;
        PrintWriter as = null;
        BufferedReader ds = null;
        BufferedReader stdIn = null;

        try {
            socket = new Socket(HOST, PORT);
            as = new PrintWriter(socket.getOutputStream(), true);  // write to server
            ds = new BufferedReader(new InputStreamReader(socket.getInputStream())); // read from server
            stdIn = new BufferedReader(new InputStreamReader(System.in));

            ClientThread clientThread = new ClientThread(socket, as, ds, stdIn);


        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
