package Usuario_do_Banco;

import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;
import Banco_Com_Criptografia.Banco;

public class Atacante extends Usuario{
    static Banco stub; 
    static Scanner teclado = new Scanner(System.in);
    public static void main(String[] args) 
    {
        /*System.out.print("Informe o nome/endereço do RMIRegistry: ");
        String host = teclado.nextLine();*/
        String host = "localhost";

        try {
            Registry registro = LocateRegistry.getRegistry(host, 20003);
            stub = (Banco) registro.lookup("Banco");
            Atacante at = new Atacante();
            menu_atacante(at.new Dados_Cliente());
        } catch (Exception e) {
            System.err.println("Cliente: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void menu_atacante(Dados_Cliente cliente) throws RemoteException
    {
        System.out.println("\n=== MENU ATACANTE ===\n");
        System.out.println("Selecione uma opção:");
        System.out.println("[1] - Forçar envio de mensagem");
        System.out.println("[2] - Analisar último pacote (sniffing)");
        int opt = teclado.nextInt();
        teclado.nextLine();

        switch(opt){
            case 1:
                System.out.print("Digite o numero da conta alvo: ");
                String numero_conta = teclado.nextLine();
                String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
                /* Resgata chaves do servidor */
                cliente.chave_vernam = stub.getChaveVernam(cpf);
                cliente.chave_aes = stub.getChaveAES(cpf);
                /* Atualiza o vetor de inicializacao e resgata o valor dele */
                stub.setVetorInit(cpf);
                cliente.vi_bytes = stub.getVetorInit(cpf);
                operacoes(cliente);
                break;
            case 2:
                System.out.println("Ultima mensagem enviada: " + last_msg);
                break;
        }

        
    }
}
