package Banco_Com_Criptografia;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class Filtro {
    
    protected static boolean filtrar_operacoes(String mensagem)
    {
        String [] operacao = mensagem.split("\\|");
        
        switch (operacao[0]) {
            case "saque":
                float saque = Float.parseFloat(operacao[1]);
                /* Sacando valor maior que o permitido */
                if(saque > 1000){
                    return false;
                }
                else{
                    return true;
                }

            case "deposito":
                float deposito = Float.parseFloat(operacao[1]);
                /* Depositando valor negativo ou igual a zero */
                if(deposito <= 0){
                    return false;
                }
                else{
                    return true;
                }

            case "transferencia":
                float valor = Float.parseFloat(operacao[1]);
                /* Transferindo valor negativo ou igual a zero */
                if(valor <= 0){
                    return false;
                }
                else{
                    return true;
                }

            default:
                return true;

        }
    }

    protected static boolean filtrar_acesso_ao_BD(String ip_cliente) 
    { 
        try {
            
            InetAddress cliente = InetAddress.getByName(ip_cliente);
            InetAddress banco = InetAddress.getByName("localhost");
            return banco.equals(cliente);

        } catch (UnknownHostException e) {
            return false;
        }
    }
}
