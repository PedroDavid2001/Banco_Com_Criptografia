package Usuario_do_Banco;

import Banco_Com_Criptografia.Autenticador;
import Banco_Com_Criptografia.Banco;
import Banco_Com_Criptografia.Cifrador;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class Usuario {
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
            login_menu();
        } catch (Exception e) {
            System.err.println("Cliente: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void login_menu() throws RemoteException
    {
        System.out.println("\n=== MENU INICIAL ===\n");
        System.out.println("Selecione uma opção:");
        System.out.println("[1] - Login");
        System.out.println("[2] - Cadastro");
        int opt = teclado.nextInt();
        teclado.nextLine();
 
        switch (opt) {
            case 1:
                while(true){
                    System.out.println("--- Tela de login ---");
                    System.out.print("Digite o numero da conta: ");
                    String numero_conta = teclado.nextLine();

                    System.out.print("Digite sua senha: ");
                    String senha = teclado.nextLine();

                    String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
                    
                    /* Resgata chaves do servidor */
                    String chave_vernam = stub.getChaveVernam(cpf);
                    SecretKey chave_aes = stub.getChaveAES(cpf);
                    /* Atualiza o vetor de inicializacao e resgata o valor dele */
                    stub.setVetorInit(cpf);
                    byte [] vi_bytes = stub.getVetorInit(cpf);
                    
                    String msg_cifrada = cifrar_autenticacao(numero_conta, senha, chave_vernam, chave_aes, vi_bytes);
                    String tag = Autenticador.gerar_tag(msg_cifrada, stub.buscar_chave_hmac(cpf));

                    if(stub.autenticar(cpf, msg_cifrada, tag)){
                        operacoes(stub.buscar_chave_hmac(cpf), cpf, chave_vernam, chave_aes, vi_bytes);
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

                /* Resgata chaves do servidor */
                String chave_vernam = stub.getChaveVernam(cpf);
                SecretKey chave_aes = stub.getChaveAES(cpf);
                /* Atualiza o vetor de inicializacao e resgata o valor dele */
                stub.setVetorInit(cpf);
                byte [] vi_bytes = stub.getVetorInit(cpf);

                String msg_cifrada = Cifrador.cifrar_mensagem(dados.toString(), cpf, chave_vernam, chave_aes, vi_bytes);
                if(stub.cadastrar(cpf, msg_cifrada)){
                    operacoes(stub.buscar_chave_hmac(cpf), cpf, chave_vernam, chave_aes, vi_bytes);
                    break;
                }else{
                    System.out.println("Usuário já está cadastrado!");
                }

                break;
        }
    }

    public static void operacoes(String chave_hmac, String cpf, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes) throws RemoteException
    {
        int opt;
        String mensagem = null;
        String valor = null;
        do{
            System.out.println("Selecione uma operação:");
            System.out.println("[1] - Saque");
            System.out.println("[2] - Depósito");
            System.out.println("[3] - Transferência");
            System.out.println("[4] - Verificar Saldo");
            System.out.println("[5] - Simular Investimento");
            System.out.println("[6] - Visualizar Perfil");
            System.out.println("[0] - Sair");
            opt = teclado.nextInt();
            teclado.nextLine();

            switch (opt) {
                case 1:
                    System.out.println("Digite o valor do saque: ");
                    valor = teclado.nextLine();
                    mensagem = "saque|" + valor;
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 2:
                    System.out.println("Digite o valor do depósito: ");
                    valor = teclado.nextLine();
                    mensagem = "deposito|" + valor;
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 3:
                    System.out.println("Digite o valor da transferência: ");
                    valor = teclado.nextLine();
                    System.out.println("Digite o número da conta do destinatário: ");
                    String destino = teclado.nextLine();
                    mensagem = "transferencia|" + valor + "|" + destino;
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 4:
                    mensagem = "saldo";
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 5:
                    mensagem = simular_investimentos();
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 6:
                    mensagem = "perfil";
                    System.out.println(troca_de_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes));
                    break;
                case 0:
                    System.out.println("Desconectando. . .");
                    break;
                default:
                    System.out.println("Opção inválida!");
                    break;
            }
            System.out.println("Enter para continuar. . .");
            teclado.nextLine();
            /* Limpa o terminal */
            System.out.print("\033[H\033[2J");
            System.out.flush();
        } while(opt != 0);
        
    }

    /* ======================================= */
    /*           TROCA DE MENSAGENS            */
    /* ======================================= */ 

    public static String troca_de_mensagem(String mensagem, String cpf, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes) throws RemoteException
    {
        /* Cifra a mensagem */
        String msg_cripto = Cifrador.cifrar_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes);
        /* Gera uma tag resgatando a chave hmac armazenada no servidor */
        String tag = Autenticador.gerar_tag(msg_cripto, stub.buscar_chave_hmac(cpf));
        /* Envia a mensagem e aguarda a resposta */
        String resposta = stub.receber_mensagem(cpf, msg_cripto, tag);
        return desempacotar_resposta(resposta, cpf, chave_vernam, chave_aes, vi_bytes);
    }

    public static String desempacotar_resposta(String resposta, String cpf, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes)  throws RemoteException
    {
        /* cripto_res + "|" + tag */
        String [] corpo_msg = resposta.split("\\|"); 
        if(Autenticador.autenticar_mensagem(corpo_msg[0], stub.buscar_chave_hmac(cpf), corpo_msg[1])){
            return Cifrador.decifrar_mensagem(corpo_msg[0], cpf, chave_vernam, chave_aes, vi_bytes);
        }
        return "Houve um erro no recebimento da mensagem!";
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    public static String cifrar_autenticacao(String numero_conta, String senha, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes) throws RemoteException
    {
        String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
        String mensagem = numero_conta + "|" + senha;
        return Cifrador.cifrar_mensagem(mensagem, cpf, chave_vernam, chave_aes, vi_bytes);
    }

    /* Metodo para decidir o tipo de investimento e a quantidade de meses */
    public static String simular_investimentos() throws RemoteException
    {
        int tipo, qnt_meses;

        /* Laços de repetição para garantir que o usuário digitará o valor certo */
        do{
            System.out.println("Selecione o tipo de investimento: ");
            System.out.println("[1] - Poupança");
            System.out.println("[2] - Renda Fixa");
            tipo = teclado.nextInt();
            teclado.nextLine();
        }while(tipo != 1 && tipo != 2);

        do{
            System.out.println("Selecione a quantidade de meses: ");
            System.out.println("[3] Meses");
            System.out.println("[6] Meses");
            System.out.println("[12] Meses");
            qnt_meses = teclado.nextInt();
            teclado.nextLine();
        }while(qnt_meses != 3 && qnt_meses != 6 && qnt_meses != 12);

        switch (tipo) {
            case 1:
                return "poupanca|" + qnt_meses;
            case 2:
                System.out.print("Digite o valor a ser investido: R$");
                float valor = teclado.nextFloat();
                teclado.nextLine();
                return "renda_fixa|" + valor + "|" + qnt_meses;
            default:
                return "Houve um erro na execução. . .";
        }
    }
}
