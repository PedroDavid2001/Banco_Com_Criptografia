package Banco_Com_Criptografia;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/* Classe utilizada para acessar os dados na base do banco */
public class Backdoor {
    static Banco stub; 
    protected static void main(String[] args) 
    {
        String host = "localhost";

        try {

            Registry registro = LocateRegistry.getRegistry(host, 20003);
            stub = (Banco) registro.lookup("Banco");
            tela_de_log();

        } catch (Exception e) {
            System.err.println("Backdoor: " + e.toString());
            e.printStackTrace();
        }
    }

    private static void tela_de_log() throws RemoteException
    {
        while (true) {
            System.out.println("Contas cadastradas na base de dados:");
            
            /* Tenta acessar os dados */
            try {
            
                System.out.println(stub.base_de_dados(InetAddress.getByName("localhost").getHostAddress()));
    
            } catch (UnknownHostException e) {
                e.printStackTrace();
            }

            /* Limpa o terminal a cada 1 segundo*/
            try {
                Thread.sleep(1000); 
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.print("\033[H\033[2J");
            System.out.flush();
        }
    }

    protected static String dados_do_banco() throws RemoteException
    {
        try {
            
            return stub.base_de_dados(InetAddress.getByName("localhost").getHostAddress());

        } catch (UnknownHostException e) {
            e.printStackTrace();
            return "Problema no backdoor";
        }
    }

}
