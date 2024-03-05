package Banco_Com_Criptografia;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;

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
} 
