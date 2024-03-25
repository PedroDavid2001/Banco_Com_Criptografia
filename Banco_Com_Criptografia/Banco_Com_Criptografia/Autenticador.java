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
    
    private static String assinar_hash(String hash, String chave_privada, String ps, String gs)
    {
        BigInteger k;
        BigInteger p = new BigInteger(ps);
        BigInteger g = new BigInteger(gs);
        BigInteger x = new BigInteger(chave_privada);
        BigInteger m = new BigInteger(hash, 16);

        /*
         * a. Gera um valor k, tal que: 1 < k < p-1.
         * 
         * b. C1 = g^k mod p.
         * 
         * c. C2 = k^-1 * (m — x * C1) mod (p-1) 
         *                      
         * >> Propriedade de multiplicação da aritmética modular:
         *   (A * B) mod C = (A mod C * B mod C) mod C
         * 
         * > C2 = [ k^-1 mod (p-1) ] * [(m — x * C1) mod (p-1)] mod (p-1)
         * 
         * d. A assinatura do hash é o par -> (C1, C2).
        */

        // Verifica se mdc(k,p - 1) = 1
        do {
            // Atribui para o "k" um número primo no intervalo [2, p - 2]
            k = BigInteger.probablePrime(p.bitLength() - 1, new SecureRandom());
        } while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger c1 = g.modPow(k, p);

        BigInteger k_inverso = k.modInverse(p.subtract(BigInteger.ONE));
        BigInteger c1_vezes_x = c1.multiply(x);
        BigInteger m_menos_c1x = m.subtract(c1_vezes_x).mod(p.subtract(BigInteger.ONE));
        BigInteger c2 = k_inverso.multiply(m_menos_c1x).mod(p.subtract(BigInteger.ONE));

        return c1.toString() + "$" + c2.toString();
    }

    private static boolean decifrar_hash(String hash_assinado, String hash, String chave_publica, String ps, String gs)
    {
        /* 
         * a. V1 = y^c1 * c1^c2 mod p
         * 
         * >> Propriedade de multiplicação da aritmética modular:
         *   (A * B) mod C = (A mod C * B mod C) mod C
         * 
         * > V1 = ( y^c1 mod p ) * ( c1^c2 mod p ) mod p
         * 
         * b. V2 = g^m mod p.
         * 
         * c. Verifica se v1 = v2. Caso sejam, a assinatura é válida. 
        */
        
        String [] c1c2 = hash_assinado.split("\\$");
        BigInteger c1 = new BigInteger(c1c2[0]);
        BigInteger c2 = new BigInteger(c1c2[1]);

        BigInteger p = new BigInteger(ps);
        BigInteger g = new BigInteger(gs);
        BigInteger y = new BigInteger(chave_publica);
        BigInteger m = new BigInteger(hash, 16);

        BigInteger y_pow_c1 = y.modPow(c1, p);
        BigInteger c1_pow_c2 = c1.modPow(c2, p);
        BigInteger v1 = y_pow_c1.multiply(c1_pow_c2).mod(p);
        
        BigInteger v2 = g.modPow(m, p);

        if(v1.compareTo(v2) == 0){
            return true;
        }

        return false;
    }

    /* ======================================= */
    /*         CIFRAGEM DE CHAVE HMAC          */
    /* ======================================= */ 

    public static String cifrar_chave_hmac(String chave, String chave_pub_dest, String ps, String gs)
    {
        BigInteger k;
        BigInteger p = new BigInteger(ps);
        BigInteger g = new BigInteger(gs);
        BigInteger y = new BigInteger(chave_pub_dest);

        /*
         * a. Gera um valor k, tal que: 1 < k < p-1.
         * 
         * b. C1 = g^k mod p
         * 
         * c. C2 = (m * y^k) mod p
         *                      
         * >> Propriedade de multiplicação da aritmética modular:
         *   (A * B) mod C = (A mod C * B mod C) mod C
         * 
         * > C2 = ( m mod p ) * (y^k mod p) mod p
         * 
         * d. A assinatura do hash é o par -> (C1, C2).
        */

        // Verifica se mdc(k,p - 1) = 1
        do {
            // Atribui para o "k" um número primo no intervalo [2, p - 2]
            k = BigInteger.probablePrime(p.bitLength() - 1, new SecureRandom());
        } while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

        BigInteger c1 = g.modPow(k, p);
        BigInteger m = new BigInteger(chave);
        BigInteger m_mod_p = m.mod(p);
        BigInteger c2 = m_mod_p.multiply(y.modPow(k, p)).mod(p);

        return c1.toString() + "|" + c2.toString();
    }

    public static String decifrar_chave_hmac(String chave_cifrada, String chave_privada, String ps)
    {
        String [] c1c2 = chave_cifrada.split("\\|");
        BigInteger c1 = new BigInteger(c1c2[0]);
        BigInteger c2 = new BigInteger(c1c2[1]);

        BigInteger p = new BigInteger(ps);
        BigInteger x = new BigInteger(chave_privada);

        /*
         * a. S = c1^x mod p
         * 
         * b. m = (c2 * s^-1) mod p
         *                      
         * >> Propriedade de multiplicação da aritmética modular:
         *   (A * B) mod C = (A mod C * B mod C) mod C
         * 
         * > m = ( c2 mod p ) * (s^-1 mod p) mod p
        */

        BigInteger s = c1.modPow(x, p);
        BigInteger s_inverso = s.modInverse(p);
        BigInteger c2_mod_p = c2.mod(p);
        BigInteger m = c2_mod_p.multiply(s_inverso).mod(p);

        // Retorna o hash sem assinatura
        return m.toString();
    }
}