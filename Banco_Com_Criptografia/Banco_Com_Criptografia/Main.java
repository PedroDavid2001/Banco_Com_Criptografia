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
            BancoImp banco = new BancoImp();
            Banco skeleton = (Banco) UnicastRemoteObject.exportObject(banco, 0);
            LocateRegistry.createRegistry(20003);

            Registry registro = LocateRegistry.getRegistry(20003);
            registro.bind("Banco", skeleton);

            System.out.println(" > Servidor pronto");

        } catch (Exception e) {
            System.err.println("Servidor: " + e.getMessage());
            e.printStackTrace();
        }   
    }
}
