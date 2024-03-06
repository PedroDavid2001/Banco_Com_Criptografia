package Banco_Com_Criptografia;

import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

/* 
  Classe responsavel por realizar: 
  > A cifragem e decifragem de mensagens;
  > A codificacao e decodificao em Base64;
  > A geracao de chaves.
*/
public class Cifrador {

    /* ======================================= */
    /*           GERACAO DE CHAVES             */
    /* ======================================= */ 
    
    private static String DIGITOS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public static SecretKey gerarChaveAES() throws NoSuchAlgorithmException
    {
        KeyGenerator gerador = KeyGenerator.getInstance("AES");
        gerador.init(192);
        return gerador.generateKey();
    }

    public static String gerarChaveVernam()
    {
        StringBuilder chave = new StringBuilder();
        for(int i = 0; i < 10; i++){
            int index = new Random().nextInt(DIGITOS.length());
            chave.append(DIGITOS.charAt(index));
        }
        return chave.toString();
    }
    
    /* ======================================= */
    /*        CODIFICAO E DECODIFICAO          */
    /* ======================================= */ 

    private static String codificar(byte[] bytes_cifrados) 
    {
        return Base64.getEncoder().encodeToString(bytes_cifrados); 
    }

    private static byte[] decodificar(String texto_Base64) 
    {
        return Base64.getDecoder().decode(texto_Base64);
    }

    /* ======================================= */
    /*               CIFRAGEM                  */
    /* ======================================= */ 

    public static String cifrar_mensagem(String mensagem, String cpf, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes)
    {
        String msg_vernam = cifra_vernam(mensagem, cpf, chave_vernam);
        byte [] bytes_cifrados = cifra_AES(msg_vernam, cpf, chave_aes, vi_bytes);
        return codificar(bytes_cifrados);
    }

    private static String cifra_vernam(String texto, String cpf, String chave)
    {
        StringBuilder cifrado = new StringBuilder();
        for(int i = 0; i < texto.length(); i++){
            char r = (char) (texto.charAt(i) ^ (i % chave.length()));
            cifrado.append(r);
        }    
        return cifrado.toString();
    }

    private static byte[] cifra_AES(String texto, String cpf, SecretKey chave, byte [] vi_bytes)
    {
        try {
            // Configura o cifrador
            Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec vi = new IvParameterSpec(vi_bytes);
            cifrador.init(Cipher.ENCRYPT_MODE, chave, vi);

            // Retorna o array de bytes cifrado
            byte [] bytes_cifrados = cifrador.doFinal(texto.getBytes());
            return bytes_cifrados;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /* ======================================= */
    /*              DECIFRAGEM                 */
    /* ======================================= */ 

    public static String decifrar_mensagem(String codificado, String cpf, String chave_vernam, SecretKey chave_aes, byte [] vi_bytes)
    {
        byte [] bytes_cifrados = decodificar(codificado);
        String msg_codificada = decifragem_AES(bytes_cifrados, cpf, chave_aes, vi_bytes);
        return decifragem_vernam(msg_codificada, cpf, chave_vernam);
    }

    private static String decifragem_vernam(String cifrado, String cpf, String chave)
    {
        return cifra_vernam(cifrado, cpf, chave);
    }

    private static String decifragem_AES(byte[] bytes_cifrados, String cpf, SecretKey chave, byte [] vi_bytes)
    {
        try{
            // Configura o decifrador
            Cipher decifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec vi = new IvParameterSpec(vi_bytes);
            decifrador.init(Cipher.DECRYPT_MODE, chave, vi);

            // Decifra o array de bytes
            byte [] bytes_decifrados = decifrador.doFinal(bytes_cifrados);

            // Retorna a mensagem decifrada
            return new String(bytes_decifrados);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

}