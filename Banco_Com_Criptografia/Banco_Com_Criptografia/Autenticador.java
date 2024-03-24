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
    
    public static String gerar_hash_assinado(String mensagem, String chave_hmac, String chave_privada, String p, String g)
    {
        String hash = gerar_tag(mensagem, chave_hmac);
        return assinar_hash(hash, chave_privada, p, g);
    }

    public static boolean autenticar_hash_assinado(String mensagem, String chave_hmac, String hash_assinado, String chave_publica, String p, String g)
    {
        String hash = gerar_tag(mensagem, chave_hmac);
        return decifrar_hash(hash_assinado, hash, chave_publica, p, g);
    }

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

    /* ======================================= */
    /*            ASSINATURA DE TAG            */
    /* ======================================= */ 
    
    private static String assinar_hash(String hash, String chave_privada, String p, String g)
    {
        BigInteger k;
        BigInteger pBI = new BigInteger(p);
        BigInteger gBI = new BigInteger(g);
        BigInteger x = new BigInteger(chave_privada);

        /*
         * a. Generate a random number k such that 1 < k < p-1.
         * b. Calculate c1 = g^k mod p.
         * c. Calculate c2 = (m — x * C1) * k^-1 mod (p-1).
         * d. The signature of the message M is the pair (c1, c2).
        */

        // Verifica se mdc(k,p - 1) = 1
        do {
            // Atribui para o "k" um número primo no intervalo [2, p - 2]
            k = BigInteger.probablePrime(pBI.bitLength() - 1, new SecureRandom());
            System.out.println("K = " + k.toString());
        } while (!k.gcd(pBI.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger c1 = gBI.modPow(k, pBI);

        BigInteger m = new BigInteger(hash, 16);
        System.out.println("M na cifragem = " + m.toString());

        BigInteger x_vezes_C1 = x.multiply(c1).mod(pBI);
        BigInteger m_menos_x_vezes_C1 = m.subtract(x_vezes_C1).mod(pBI);
        BigInteger k_inverso = k.modInverse(pBI.subtract(BigInteger.ONE));

        BigInteger c2 = m_menos_x_vezes_C1.multiply(k_inverso).mod(pBI.subtract(BigInteger.ONE));

        return c1.toString() + "|" + c2.toString();
    }

    private static boolean decifrar_hash(String hash_assinado, String hash, String chave_publica, String p, String g)
    {
        /* 
         * a. Verify that 1 < r < p-1 and 0 < s < p-1. If either condition is not satisfied, the signature is invalid.
         * b. Calculate v1 = (y^c1 * c1^c2) mod p.
         * c. Calculate v2 = g ^ m mod p.
         * d. If v1 = v2, the signature is valid. Otherwise, the signature is invalid.
        */
        
        // Obtenção de C1 e C2
        String [] c1c2 = hash_assinado.split("\\|");
        BigInteger c1 = new BigInteger(c1c2[0]);
        BigInteger c2 = new BigInteger(c1c2[1]);

        // Obtenção de p, g e a chave publica
        BigInteger pBI = new BigInteger(p);
        BigInteger gBI = new BigInteger(g);
        BigInteger y = new BigInteger(chave_publica);

        if (c1.compareTo(BigInteger.ONE) <= 0 || 
            c1.compareTo(pBI.subtract(BigInteger.ONE)) >= 0 || 
            c2.compareTo(BigInteger.ONE) <= 0 || 
            c2.compareTo(pBI.subtract(BigInteger.ONE)) >= 0) {
            return false; 
        }

        BigInteger m = new BigInteger(hash, 16);
        System.out.println("M na cifragem = " + m.toString());

        BigInteger y_elev_c1 = y.modPow(c1, pBI);
        BigInteger c1_elev_c2 = c1.modPow(c2, pBI);
        BigInteger v1 = y_elev_c1.multiply(c1_elev_c2).mod(pBI);
        System.out.println("V1 = " + v1.toString());

        BigInteger v2 = gBI.modPow(m, pBI);
        System.out.println("V2 = " + v2.toString());

        if(v1.compareTo(v2) == 0){
            return true;
        }

        return false;
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