package Usuario_do_Banco;

import Banco_Com_Criptografia.Autenticador;
import Banco_Com_Criptografia.Banco;
import Banco_Com_Criptografia.Cifrador;
import Banco_Com_Criptografia.Servidor;
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

            Servidor servidor = Servidor.getInstancia();
            Cifrador cifrador = Cifrador.getInstancia(servidor);

            login_menu(stub, cifrador, servidor);
        } catch (Exception e) {
            System.err.println("Cliente: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void login_menu( Banco stub, Cifrador cifrador, Servidor servidor ) throws RemoteException
    {
        System.out.println("\n=== MENU INICIAL ===\n");
        System.out.println("Selecione uma opção:");
        System.out.println("[1] - Login");
        System.out.println("[2] - Cadastro");
        int opt = teclado.nextInt();
        teclado.nextLine();
            /* Tipos de mensagem:
            * > "autenticar|${numero_conta}|${senha}"
            * > "cadastrar"
            * > "saque|${valor}"
            * > "deposito|${valor}" 
            * > "transferencia|${valor}|${numero_conta(destino)}" 
            * > "saldo"
            * > "poupanca|${meses}"
            * > "renda_fixa|${valor}|${meses}"
            */
        switch (opt) {
            case 1:
                while(true){
                    System.out.println("--- Tela de login ---");
                    System.out.print("Digite o numero da conta: ");
                    String numero_conta = teclado.nextLine();

                    System.out.print("Digite sua senha: ");
                    String senha = teclado.nextLine();

                    String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
                    String msg_cifrada = cifrar_autenticacao(cifrador, numero_conta, senha);
                    String tag = Autenticador.gerar_tag(msg_cifrada, stub.buscar_chave_hmac(cpf));

                    if(stub.autenticar(cpf, msg_cifrada, tag)){
                        operacoes(stub.buscar_chave_hmac(cpf), cpf);
                        break;
                    }else{
                        System.out.println("Dados incorretos!");
                    }
                }
                break;
            case 2:
                StringBuilder dados = new StringBuilder();

                System.out.println("--- Tela de cadastro ---");
                System.out.print("Digite o seu nome: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite o seu CPF: ");
                String cpf = teclado.nextLine();
                dados.append( cpf + "|" );

                System.out.print("Digite o seu endereço: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite o seu telefone: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite a sua senha: ");
                dados.append( teclado.nextLine());

                String msg_cifrada = cifrar_mensagem(cifrador, dados.toString(), cpf);

                if(stub.cadastrar(cpf, msg_cifrada)){
                    operacoes(stub.buscar_chave_hmac(cpf), cpf);
                    break;
                }else{
                    System.out.println("Usuário já está cadastrado!");
                }

                break;
        }
    }

    public static void operacoes(String chave_hmac, String cpf) throws RemoteException
    {
        /* IMPLEMENTAR OPERACOES */
    }

    /* ======================================= */
    /*           TROCA DE MENSAGENS            */
    /* ======================================= */ 

    

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    public static String cifrar_autenticacao(Cifrador cifrador, String numero_conta, String senha) throws RemoteException
    {
        String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
        String mensagem = numero_conta + "|" + senha;
        return cifrador.cifrar_mensagem(mensagem, cpf);
    }

    public static String cifrar_mensagem(Cifrador cifrador, String mensagem, String cpf) throws RemoteException
    {
        return cifrador.cifrar_mensagem(mensagem, cpf);
    }

    public static String empacotar_mensagem(String mensagem, String chave) throws RemoteException
    {
        return Autenticador.gerar_tag(mensagem, chave);
    }
}
