package Usuario_do_Banco;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Scanner;
import Banco_Com_Criptografia.Banco;
import Banco_Com_Criptografia.Autenticador;

public class Atacante extends Usuario{
    static Banco stub; 
    static Scanner teclado = new Scanner(System.in);
    public static void main(String[] args) 
    {
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
        while(true){
            System.out.println("\n=== MENU ATACANTE ===\n");
            System.out.println("Selecione uma opção:");
            System.out.println("[1] - Forçar envio de mensagem");
            System.out.println("[2] - Analisar último pacote (sniffing)");
            System.out.println("[3] - Tentar acessar dados do banco diretamente");
            System.out.println("[4] - Tentar acessar backdoor");
            System.out.println("[0] - Sair");
            int opt = teclado.nextInt();
            teclado.nextLine();
    
            switch(opt){
                case 1:
                    System.out.print("Digite o numero da conta alvo: ");
                    String numero_conta = teclado.nextLine();

                    cliente.cpf = stub.buscar_cpf_na_autenticacao(numero_conta);
                    /* Realiza identificação */
                    if (cliente.cpf.equals("no_cpf")) {
                        System.out.println("Conta não identificada no sistema!");
                        return;
                    /* Verifica se já não está logado */
                    }else if(cliente.cpf.equals("logged")) {
                        System.out.println("Conta já está logada no sistema!");
                        return;
                    }

                    System.out.println("cpf da conta alvo = " + cliente.cpf);

                    /* Resgata chaves do servidor */
                    cliente.chave_vernam = stub.getChaveVernam(cliente.cpf);
                    cliente.chave_aes = stub.getChaveAES(cliente.cpf);
                    /* Resgata valores de YPG do banco */
                    BigInteger [] ypg_banco = capturar_chave_publica_do_banco(cliente.cpf);
                    /* Atualiza o vetor de inicializacao e resgata o valor dele */
                    cliente.vi_bytes = stub.getVetorInit(cliente.cpf);
    
                    System.out.println("Digite a mensagem capturada: ");
                    String msg_cripto = teclado.nextLine();
                    System.out.println("Digite o valor de p: ");
                    String p = teclado.nextLine();
                    System.out.println("Digite o valor de g: ");
                    String g = teclado.nextLine();
                    
                    try {
                        String tag_assinado = Autenticador.gerar_hash_assinado(
                                                                                msg_cripto, 
                                                                                cliente.chave_hmac, 
                                                                                /* Atacante não tem acesso 
                                                                                a chave privada do usuario */
                                                                                "1", 
                                                                                p, 
                                                                                g
                                                                            );
                        /* Envia a mensagem e aguarda a resposta */
                        String resposta = stub.receber_mensagem(cliente.cpf, msg_cripto, tag_assinado); 
                        if(resposta.equals("not_logged")){
                            System.out.println("Seu acesso não foi autorizado! Operação não realizada");
                        }else{
                            System.out.println(desempacotar_resposta(resposta, cliente, ypg_banco));
                        }
                        
                    } catch (NullPointerException e){
                        System.out.println("Não obteve resposta do servidor!");
                    }
    
                    break;
                case 2:
                    System.out.println("Ultima mensagem enviada:\n    " + stub.last_msg());
                    System.out.println("Valor de \"p\": " + stub.last_p());
                    System.out.println("Valor de \"g\": " + stub.last_g());
                    break;
                case 3:
                    try {
                
                        System.out.println(stub.base_de_dados(InetAddress.getByName("localhost").getHostAddress()));
            
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                    break;
                case 4:
                    try {
                
                        System.out.println(stub.acessar_backdoor(InetAddress.getByName("localhost").getHostAddress()));
            
                    } catch (UnknownHostException e) {
                        e.printStackTrace();
                    }
                    break;
                case 0:
                    return;
            }
        }
    }

    public static BigInteger[] capturar_chave_publica_do_banco(String cpf) throws RemoteException
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
}
