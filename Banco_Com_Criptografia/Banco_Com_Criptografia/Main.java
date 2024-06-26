package Banco_Com_Criptografia;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;

public class Main {
    
    public static void config()
    {
        System.setProperty("java.rmi.server.hostname", "127.0.0.1");
        System.setProperty("java.security.policy", "java.policy");
    }

    public static void main(String[] args) {
        config();

        try {
            /* Inicia relogio */
            Relogio relogio = new Relogio();
            relogio.start();

            BancoImp banco = new BancoImp(relogio);
            Banco skeleton = (Banco) UnicastRemoteObject.exportObject(banco, 0);
            LocateRegistry.createRegistry(20033);

            Registry registro = LocateRegistry.getRegistry(20033);
            registro.bind("Banco", skeleton);

            System.out.println(" > Servidor pronto");

        } catch (Exception e) {
            System.err.println("Servidor: " + e.getMessage());
            e.printStackTrace();
        }   
    }
}
