package Cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class ClienteMain {

    private static final int PORT = 4030; 
    private static final String HOST = "localhost";

    public static void main(String[] args) {

        Socket socket = null;
        PrintWriter as = null;
        BufferedReader ds = null;
        BufferedReader stdIn = null;

        try {

            System.out.println("ENTER THE NUMBER OF CLIENTS: ");
            Scanner s = new Scanner(System.in);
            int clie = s.nextInt();

            for (int i =0; i <clie; i++) {
                socket = new Socket(HOST, PORT);
                as = new PrintWriter(socket.getOutputStream(), true);  // write to server
                ds = new BufferedReader(new InputStreamReader(socket.getInputStream())); // read from server
                stdIn = new BufferedReader(new InputStreamReader(System.in));


                System.out.println("Creating client thread...");
                ClientThread clientThread = new ClientThread(socket, as, ds, stdIn);
                clientThread.start();
            }



        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
