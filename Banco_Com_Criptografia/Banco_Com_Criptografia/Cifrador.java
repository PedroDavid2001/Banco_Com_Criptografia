package Banco_Com_Criptografia;

import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
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
    protected static final BigInteger UM = BigInteger.ONE;
    protected static final BigInteger DOIS = new BigInteger("2");
    protected static final BigInteger TRES = new BigInteger("3");
    
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

    public static String gerarChavesElGamal()
    {
        // Numero primo com aproximadamente 617 digitos decimais
        BigInteger p = BigInteger.probablePrime(2048, new SecureRandom());
        
        // Valor utilizado como expoente para verificar se "g" é coprimo de "p".
        // O calculo (p-1/2) garante que o valor de p' sera par e estara no limiar 
        // [2, p - 2]
        BigInteger p_primo = p.subtract(UM).divide(DOIS);

        // Numero coprimo de "p" e que, ao ser elevado a diferentes potências, gere 
        // todos os elementos não nulos do grupo multiplicativo (Z/pZ)*.
        BigInteger g;

        // Define um valor para "g", tal que: (g ^ p') mod p = 1
        do {
            // A cada iteracao é atribuido a "g" um valor aleatorio dentro do 
            // intervalo [2, p - 2]
            
            // Para alcançar tal valor é feito:
            // I - Gera um valor BigInteger dentro do intervalo [0, (2 ^ numBits - 1)];
            //
            // II - Descobre o resto da divisão deste valor encontrado com p - 3;
            // (Devido o 'mod' retornar sempre um valor entre 0 e o máximo, que é p - 3, 
            // neste caso, o intervalo do valor resultante será: [0, p − 4])
            //
            // III - O resultado do módulo é somado com 2.
            g = DOIS.add(new BigInteger(p.bitLength(), new SecureRandom()).mod(p.subtract(TRES)));
        } while (!g.modPow(p_primo, p).equals(UM));
        
        // Chave privada dentro do intervalo [2, p - 2]
        BigInteger x = DOIS.add(new BigInteger(p.bitLength(), new SecureRandom()).mod(p.subtract(TRES)));
        
        // Chave publica -> y = (g ^ x) mod p 
        BigInteger y = g.modPow(x, p);

        /* Retorno esperado: ${x}|${y}|${p}|${g} */
        return x.toString() + "|" + y.toString() + "|" + p.toString() + "|" + g.toString();
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