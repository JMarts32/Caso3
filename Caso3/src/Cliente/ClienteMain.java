package Cliente;

import java.io.IOException;
import java.net.Socket;

public class ClienteMain {

    private static final int PORT = 4030; 
    private static final String HOST = "localhoåst";

    public static void main(String[] args) {

        Socket socket = null;

        try {
            socket = new Socket(HOST, PORT);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}
