package Usuario_do_Banco;

import Banco_Com_Criptografia.Banco;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

public class Usuario {
    static Banco stub; 
    static Scanner teclado = new Scanner(System.in);

    public static void main(String[] args) 
    {
        System.out.print("Informe o nome/endereço do RMIRegistry: ");
        String host = teclado.nextLine();

        try {
            Registry registro = LocateRegistry.getRegistry(host, 20003);
            stub = (Banco) registro.lookup("Banco");
            login_menu(stub);
        } catch (Exception e) {
            System.err.println("Cliente: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void login_menu( Banco stub ) throws RemoteException
    {
        
    }
}
