package Banco_Com_Criptografia;

import java.rmi.Remote;
import java.rmi.RemoteException;
import javax.crypto.SecretKey;

/*
 * Banco será responsável por:
 * > Armazenar os dados das contas cadastradas;
 * > Receber mensagens, autenticar a 
 * integridade delas e realizar alguma operacao;
 * 
 * Tipos de mensagem:
 * > "autenticar|${numero_conta}|${senha}"
 * > "cadastrar|${cliente.toString()}"
 * > "saque|${valor}"
 * > "deposito|${valor}" 
 * > "transferencia|${valor}" 
 * > "saldo"
 * > "poupanca|${meses}"
 * > "renda_fixa|${meses}"
 */
public interface Banco extends Remote{
    String receber_mensagem(String cpf, String msg_cripto, String tag_recebida) throws RemoteException;
    String enviar_mensagem(String cpf, String mensagem, String chave) throws RemoteException;
    boolean autenticar(String cpf, String msg_cifrada, String tag_recebida) throws RemoteException;
    boolean cadastrar(String cpf, String msg_cifrada) throws RemoteException;
    String buscar_cpf_na_autenticacao(String numero_conta) throws RemoteException;
    String buscar_chave_hmac(String senha, String cpf, String p_cli, String g_cli) throws RemoteException;
    String getChaveVernam(String cpf) throws RemoteException;
    SecretKey getChaveAES(String cpf) throws RemoteException;
    byte [] getVetorInit(String cpf) throws RemoteException;
    void setVetorInit(String cpf) throws RemoteException;
    String divulgar_chave_publica(String cpf) throws RemoteException;
    void receber_chave_publica( String ypg, String cpf, String senha ) throws RemoteException;
    String last_msg() throws RemoteException;
    String last_p() throws RemoteException;
    String last_g() throws RemoteException;
} 
