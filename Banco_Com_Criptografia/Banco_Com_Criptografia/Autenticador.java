package Banco_Com_Criptografia;

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
  Classe em que sao realizados os metodos de autenticacao 
  de mensagens trocadas com base nos codigos hash gerados 
  e enviados.
*/
public class Autenticador {

    /* ======================================= */
    /*      GERACAO E AUTENTICACAO DE TAG      */
    /* ======================================= */
    
    public static String gerar_hash_assinado(String mensagem, String chave, String chave_privada, String p, String g)
    {
        String hash = gerar_tag(mensagem, chave);
        return assinar_hash(hash, chave_privada, p, g);
    }

    public static boolean autenticar_hash_assinado(String hash_assinado, String chave_publica, String p)
    {
        String hash = decifrar_hash(hash_assinado, chave_publica, p);
    }

    private static String gerar_tag(String mensagem, String chave)
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
    
    private static boolean autenticar_mensagem(String mensagem, String chave, String tag_recebida) {
        String tag_calculada = gerar_tag(mensagem, chave);
        return tag_calculada.equals(tag_recebida);
    }

    /* ======================================= */
    /*            ASSINATURA DE TAG            */
    /* ======================================= */ 
    
    private static String assinar_hash(String hash, String chave_privada, String p, String g)
    {
        BigInteger k;
        BigInteger pBI = new BigInteger(p);
        BigInteger gBI = new BigInteger(g);
        BigInteger x = new BigInteger(chave_privada);

        // Verifica se mdc(k,p - 1) = 1
        do {
            // Atribui para o "k" um número primo no intervalo [2, p - 2]
            k = BigInteger.probablePrime(pBI.bitLength() - 1, new SecureRandom());
        } while (!k.gcd(pBI.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger c1 = gBI.modPow(k, pBI);
        BigInteger m = new BigInteger(hash, 16);
        BigInteger c2 = m.multiply(x.modPow(k, pBI)).mod(pBI);

        return c1.toString() + "|" + c2.toString();
    }

    private static String decifrar_hash(String hash_assinado, String chave_publica, String p)
    {
        // Obtenção de C1 e C2
        String [] c1c2 = hash_assinado.split("\\|");
        BigInteger c1 = new BigInteger(c1c2[0]);
        BigInteger c2 = new BigInteger(c1c2[1]);

        // Obtenção de p e a chave privada
        BigInteger pBI = new BigInteger(p);
        BigInteger y = new BigInteger(chave_publica);

        // Decifragem
        BigInteger s = c1.modPow(y, pBI);
        BigInteger s_inverso = s.modInverse(pBI);
        BigInteger m = c2.multiply(s_inverso).mod(pBI);

        // Retorna o hash sem assinatura
        return m.toString();
    }

    /* ======================================= */
    /*         CIFRAGEM DE CHAVE HMAC          */
    /* ======================================= */ 

    public static String cifrar_chave_hmac(String chave, String chave_pub_dest, String p, String g)
    {
        BigInteger k;
        BigInteger pBI = new BigInteger(p);
        BigInteger gBI = new BigInteger(g);
        /* Chave pública do destinatário usada para cifrar a chave */
        BigInteger y = new BigInteger(chave_pub_dest);

        // Verifica se mdc(k,p - 1) = 1
        do {
            // Atribui para o "k" um número primo no intervalo [2, p - 2]
            k = BigInteger.probablePrime(pBI.bitLength() - 1, new SecureRandom());
        } while (!k.gcd(pBI.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger c1 = gBI.modPow(k, pBI);
        /* Objeto BigInteger relativo a chave */
        BigInteger chaveBI = new BigInteger(chave);
        BigInteger c2 = chaveBI.multiply(y.modPow(k, pBI)).mod(pBI);

        return c1.toString() + "|" + c2.toString();
    }

    public static String decifrar_chave_hmac(String chave_cifrada, String chave_privada, String p)
    {
        // Obtenção de C1 e C2
        String [] c1c2 = chave_cifrada.split("\\|");
        BigInteger c1 = new BigInteger(c1c2[0]);
        BigInteger c2 = new BigInteger(c1c2[1]);

        // Obtenção de p e a chave privada
        BigInteger pBI = new BigInteger(p);
        BigInteger x = new BigInteger(chave_privada);

        // Decifragem
        BigInteger s = c1.modPow(x, pBI);
        BigInteger s_inverso = s.modInverse(pBI);
        BigInteger m = c2.multiply(s_inverso).mod(pBI);

        // Retorna o hash sem assinatura
        return m.toString();
    }
}