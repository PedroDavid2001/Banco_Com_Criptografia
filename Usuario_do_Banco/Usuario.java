package Usuario_do_Banco;

import Banco_Com_Criptografia.Autenticador;
import Banco_Com_Criptografia.Banco;
import Banco_Com_Criptografia.Cifrador;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class Usuario {
    public static Banco stub; 
    public static Scanner teclado = new Scanner(System.in);

    /* Classe utilizada para armazenar os dados de cada usuario durante sua execução */
    protected class Dados_Cliente {
        SecretKey chave_aes;
        String chave_vernam; 
        String chave_hmac;
        byte [] vi_bytes;
        String cpf;
        BigInteger[] xypg;
        String senha;
    }

    public static void main(String[] args) 
    {
        /*System.out.print("Informe o nome/endereço do RMIRegistry: ");
        String host = teclado.nextLine();*/
        String host = "localhost";

        try {
            Registry registro = LocateRegistry.getRegistry(host, 20003);
            stub = (Banco) registro.lookup("Banco");
            Usuario usu = new Usuario();
            login_menu(usu.new Dados_Cliente());
        } catch (Exception e) {
            System.err.println("Cliente: " + e.toString());
            e.printStackTrace();
        }
    }

    public static void login_menu(Dados_Cliente cliente) throws RemoteException
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
                    System.out.println("\n--- Tela de login ---");
                    System.out.print("Digite o numero da conta: ");
                    String numero_conta = teclado.nextLine();

                    System.out.print("Digite sua senha: ");
                    cliente.senha = teclado.nextLine();

                    cliente.cpf = stub.buscar_cpf_na_autenticacao(numero_conta);

                    /* Gera chaves assimetricas e envia a chave publica, "p" e "g" para o banco */
                    cliente.xypg = gerar_chaves_assimetricas(cliente);
                    
                    /* Resgata chaves do servidor */
                    cliente.chave_vernam = stub.getChaveVernam(cliente.cpf);
                    cliente.chave_aes = stub.getChaveAES(cliente.cpf);
                    /* Resgata o valor do vetor de inicialização */
                    cliente.vi_bytes = stub.getVetorInit(cliente.cpf);
                    
                    /* Resgata chave hmac do cliente */
                    cliente.chave_hmac = Autenticador.decifrar_chave_hmac (
                        stub.buscar_chave_hmac(
                                                cliente.senha, 
                                                cliente.cpf, 
                                                cliente.xypg[2].toString(), 
                                                cliente.xypg[3].toString()
                                            ), 
                        cliente.xypg[0].toString(), 
                        cliente.xypg[2].toString()
                    );

                    String msg_cifrada = cifrar_autenticacao(numero_conta, cliente.senha, cliente);
                    String tag = Autenticador.gerar_tag(msg_cifrada, cliente.chave_hmac);

                    if(stub.autenticar(cliente.cpf, msg_cifrada, tag)){
                        /* Atualiza o vetor de inicializacao para iniciar as operações */
                        stub.setVetorInit(cliente.cpf);
                        cliente.vi_bytes = stub.getVetorInit(cliente.cpf);
                        operacoes(cliente);
                        break;
                    }else{
                        System.out.println("\nNão foi possível realizar o login!");
                    }
                }
                break;
            case 2:
                StringBuilder dados = new StringBuilder();

                System.out.println("--- Tela de cadastro ---");
                System.out.print("Digite o seu nome: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite o seu CPF: ");
                cliente.cpf = teclado.nextLine();
                dados.append( cliente.cpf + "|" );

                System.out.print("Digite o seu endereço: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite o seu telefone: ");
                dados.append( teclado.nextLine() + "|" );

                System.out.print("Digite a sua senha: ");
                cliente.senha = teclado.nextLine();
                dados.append(cliente.senha);

                /* Resgata chaves do servidor */
                cliente.chave_vernam = stub.getChaveVernam(cliente.cpf);
                cliente.chave_aes = stub.getChaveAES(cliente.cpf);
                /* Atualiza o vetor de inicializacao e resgata o valor dele */
                stub.setVetorInit(cliente.cpf);
                cliente.vi_bytes = stub.getVetorInit(cliente.cpf);

                String msg_cifrada = Cifrador.cifrar_mensagem(
                                                                dados.toString(), 
                                                                cliente.cpf, 
                                                                cliente.chave_vernam, 
                                                                cliente.chave_aes, 
                                                                cliente.vi_bytes
                                                            );
                if(stub.cadastrar(cliente.cpf, msg_cifrada)){
                    /* Gera chaves assimetricas e envia a chave publica, "p" e "g" para o banco */
                    cliente.xypg = gerar_chaves_assimetricas(cliente);
                    /* Resgata chave hmac do cliente */
                    String chave_hmac_cifrada = stub.buscar_chave_hmac(
                                                                        cliente.senha, 
                                                                        cliente.cpf, 
                                                                        cliente.xypg[2].toString(), 
                                                                        cliente.xypg[3].toString()
                                                                    );
                    cliente.chave_hmac = Autenticador.decifrar_chave_hmac (
                                                                            chave_hmac_cifrada, 
                                                                            cliente.xypg[0].toString(), 
                                                                            cliente.xypg[2].toString()
                                                                        );

                    operacoes(cliente);
                    break;
                }else{
                    System.out.println("Usuário já está cadastrado!");
                }

                break;
        }
    }

    public static void operacoes(Dados_Cliente cliente) throws RemoteException
    {
        /* Antes de enviar uma mensagem, resgata os dados do destinatario (banco) */
        BigInteger[] ypg_banco = receber_chave_publica_do_banco(cliente.cpf);
        
        int opt;
        String mensagem = null;
        String valor = null;

        /* Limpa o terminal */
        System.out.print("\033[H\033[2J");
        System.out.flush();

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
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 2:
                    System.out.println("Digite o valor do depósito: ");
                    valor = teclado.nextLine();
                    mensagem = "deposito|" + valor;
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 3:
                    System.out.println("Digite o valor da transferência: ");
                    valor = teclado.nextLine();
                    System.out.println("Digite o número da conta do destinatário: ");
                    String destino = teclado.nextLine();
                    mensagem = "transferencia|" + valor + "|" + destino;
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 4:
                    mensagem = "saldo";
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 5:
                    mensagem = simular_investimentos();
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 6:
                    mensagem = "perfil";
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                case 0:
                    System.out.println("Desconectando. . .");
                    mensagem = "sair";
                    System.out.println(troca_de_mensagem(ypg_banco, mensagem, cliente));
                    break;
                default:
                    System.out.println("Operacao invalida!");
                    break;
            }

            System.out.println("\nEnter para continuar. . .");
            teclado.nextLine();

            /* Limpa o terminal */
            System.out.print("\033[H\033[2J");
            System.out.flush();
            
        } while(opt != 0);
        
    }

    /* ======================================= */
    /*           TROCA DE MENSAGENS            */
    /* ======================================= */ 

    public static String troca_de_mensagem(BigInteger [] ypg_banco, String mensagem, Dados_Cliente cliente) throws RemoteException
    {
        /* Se resposta está null, então o banco não respondeu a mensagem */
        try{
            /* Cifra a mensagem */
            String msg_cripto = Cifrador.cifrar_mensagem(mensagem, cliente.cpf, cliente.chave_vernam, cliente.chave_aes, cliente.vi_bytes);
            /* Gera uma tag resgatando a chave hmac armazenada no servidor */
            String tag_assinado = Autenticador.gerar_hash_assinado(
                                                                    msg_cripto, 
                                                                    cliente.chave_hmac, 
                                                                    cliente.xypg[0].toString(), 
                                                                    cliente.xypg[2].toString(), 
                                                                    cliente.xypg[3].toString()
                                                                );
            /* Envia a mensagem e aguarda a resposta */
            String resposta = stub.receber_mensagem(cliente.cpf, msg_cripto, tag_assinado);
            return desempacotar_resposta(resposta, cliente, ypg_banco);

        }catch(NullPointerException e){
            e.printStackTrace();
            return "Não obteve resposta do servidor!";
        }
    }

    public static String desempacotar_resposta(String resposta, Dados_Cliente cliente, BigInteger [] ypg_banco)  throws RemoteException
    {
        /* cripto_res + "|" + tag_assinada */
        String [] corpo_msg = resposta.split("\\|"); 
        if(Autenticador.autenticar_hash_assinado(
                                                    corpo_msg[0], 
                                                    cliente.chave_hmac, 
                                                    corpo_msg[1], 
                                                    ypg_banco[0].toString(), 
                                                    ypg_banco[1].toString(), 
                                                    ypg_banco[2].toString()
                                                )){
            return Cifrador.decifrar_mensagem(corpo_msg[0], cliente.cpf, cliente.chave_vernam, cliente.chave_aes, cliente.vi_bytes);
        }
        return "Houve um erro no recebimento da mensagem!";
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    public static BigInteger[] gerar_chaves_assimetricas(Dados_Cliente cliente) throws RemoteException
    {
        BigInteger [] XYPG = new BigInteger[4];

        String [] chaves = Cifrador.gerarChavesElGamal().split("\\|");
        XYPG[0] = new BigInteger(chaves[0]);
        XYPG[1] = new BigInteger(chaves[1]);
        XYPG[2] = new BigInteger(chaves[2]);
        XYPG[3] = new BigInteger(chaves[3]);
        
        /* 
         * Antes de iniciar as operações, o usuário envia a chave pública, "p" e "g" para o banco
         * (Para quando receber respostas do banco)
        */
        String ypg = XYPG[1].toString() + "|" + XYPG[2].toString() + "|" + XYPG[3].toString();
        stub.receber_chave_publica( ypg, cliente.cpf, cliente.senha );

        return XYPG;
    }

    public static BigInteger[] receber_chave_publica_do_banco(String cpf) throws RemoteException
    {
        /*
        * Recebe os dados do banco
        */
        String ypg_b = stub.divulgar_chave_publica(cpf);
        
        if(ypg_b.isBlank()){
            System.out.println("Seu cpf não está cadastrado no sistema!");
            return null;
        }

        String [] ypg_banco = ypg_b.split("\\|");
        BigInteger [] YPG = {
                                new BigInteger(ypg_banco[0]), 
                                new BigInteger(ypg_banco[1]), 
                                new BigInteger(ypg_banco[2])
                            };
        return YPG;
    }


    public static String cifrar_autenticacao(String numero_conta, String senha, Dados_Cliente cliente) throws RemoteException
    {
        String cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
        String mensagem = numero_conta + "|" + senha;
        return Cifrador.cifrar_mensagem(mensagem, cpf, cliente.chave_vernam, cliente.chave_aes, cliente.vi_bytes);
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
