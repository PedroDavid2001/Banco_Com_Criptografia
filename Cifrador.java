/* 
 Classe responsavel por realizar a cifragem e decifragem de 
 mensagens, bem como a codificacao e decodificao em Base64.
*/

import java.util.Base64;

public class Cifrador {
    
    private static String codificar(String texto) 
    {
        byte[] bytesTXT = texto.getBytes();
        return Base64.getEncoder().encodeToString(bytesTXT); 
    }

    private static String decodificar(String textoB64) 
    {
        String texto = new String(Base64.getDecoder().decode(textoB64));
        return texto; 
    }

    private static String cifra_vernam(String texto, String chave)
    {
        StringBuilder cifrado = new StringBuilder();
        for(int i = 0; i < texto.length(); i++){
            char r = (char) (texto.charAt(i) ^ (i % chave.length()));
            cifrado.append(r);
        }    
        return cifrado.toString();
    }

    private static String decifragem_vernam(String cifrado, String chave)
    {
        return cifra_vernam(cifrado, chave);
    }
}
