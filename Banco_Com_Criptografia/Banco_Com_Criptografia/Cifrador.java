package Banco_Com_Criptografia;

import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
    private static Banco bc;

    public static void carregar_banco(Banco banco){
        bc = banco;
    }

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

    public static String cifrar_mensagem(String mensagem, String cpf) throws RemoteException
    {
        String msg_vernam = cifra_vernam(mensagem, cpf);
        byte [] bytes_cifrados = cifra_AES(msg_vernam, cpf);
        return codificar(bytes_cifrados);
    }

    private static String cifra_vernam(String texto, String cpf) throws RemoteException
    {
        String chave = bc.getChaveVernam(cpf);
        StringBuilder cifrado = new StringBuilder();
        for(int i = 0; i < texto.length(); i++){
            char r = (char) (texto.charAt(i) ^ (i % chave.length()));
            cifrado.append(r);
        }    
        return cifrado.toString();
    }

    private static byte[] cifra_AES(String texto, String cpf) throws RemoteException
    {
        try {
            // Resgata a chave e atualiza o vetor de 
            // inicializacao relativo ao cpf do cliente
            SecretKey chave = bc.getChaveAES(cpf);
            bc.setVetorInit(cpf, gerar_vetor_inicializacao());

            System.out.println("Chave = " + chave.toString());
            System.out.println("Vetor = " + bc.getVetorInit(cpf).toString());

            // Configura o cifrador
            Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cifrador.init(Cipher.ENCRYPT_MODE, chave, bc.getVetorInit(cpf));

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

    public static String decifrar_mensagem(String codificado, String cpf) throws RemoteException
    {
        byte [] bytes_cifrados = decodificar(codificado);
        String msg_codificada = decifragem_AES(bytes_cifrados, cpf);
        return decifragem_vernam(msg_codificada, cpf);
    }

    private static String decifragem_vernam(String cifrado, String cpf) throws RemoteException
    {
        return cifra_vernam(cifrado, cpf);
    }

    private static String decifragem_AES(byte[] bytes_cifrados, String cpf) throws RemoteException
    {
        try{
            // Resgata a chave
            SecretKey chave = bc.getChaveAES(cpf);
            System.out.println("Chave = " + chave.toString());
            System.out.println("Vetor = " + bc.getVetorInit(cpf).toString());

            // Configura o decifrador
            Cipher decifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decifrador.init(Cipher.DECRYPT_MODE, chave, bc.getVetorInit(cpf));

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

    /* ======================================= */
    /*    GERACAO DE VETOR DE INICIALIZACAO    */
    /* ======================================= */ 

    public static IvParameterSpec gerar_vetor_inicializacao()
    {
        byte [] vi = new byte[16];
        new SecureRandom().nextBytes(vi);
        return new IvParameterSpec(vi);
    }
}