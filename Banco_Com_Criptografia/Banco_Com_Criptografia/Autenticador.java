package Banco_Com_Criptografia;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
  Classe em que sao realizados os metodos de autenticacao 
  de mensagens trocadas com base nos codigos hash gerados 
  e enviados.
*/
public class Autenticador {
    public static String gerar_tag(String mensagem, String chave)
    {
        try {
            Mac hMac = Mac.getInstance("HmacSHA256");
            SecretKeySpec chaveMac = new SecretKeySpec(chave.getBytes("UTF-8"), hMac.getAlgorithm());
           
            hMac.init(chaveMac);
            byte [] bytesHMAC = hMac.doFinal(mensagem.getBytes("UTF-8"));
            
            StringBuilder sb = new StringBuilder();
            for(byte b: bytesHMAC)
                sb.append(String.format("%02x", b));
            return sb.toString();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean autenticar_mensagem(String mensagem, String chave, String tag_recebida) {
        String tag_calculada = gerar_tag(mensagem, chave);
        return tag_calculada.equals(tag_recebida);
    }
}