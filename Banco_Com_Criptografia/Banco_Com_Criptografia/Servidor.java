package Banco_Com_Criptografia;

import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/*
  Classe responsavel por controlar a geracao e distribuicao 
  de chaves e vetores de inicializacao. 
*/
public final class Servidor {
    /* Chave = CPF do usuário, Value = chave AES */
    private Map<String, SecretKey> chavesAES = null;
    /* Chave = CPF do usuário, Value = chave Vernam */
    private Map<String, String> chavesVernam = null;
    /* Chave = CPF do usuário, Value = vetor de inicializacao (temporario) */
    private Map<String, IvParameterSpec> vetores_init = null;
    /* Chave = CPF do usuário, Value = chave HMAC */
    private Map<String, String> chaves_hmac = null;
    
    private Servidor()
    {
        chavesAES = new HashMap<String, SecretKey>();
        chavesVernam = new HashMap<String, String>();
        vetores_init = new HashMap<String, IvParameterSpec>();
        chaves_hmac = new HashMap<String, String>();
    }

    // Aplicacao de padrão Singleton para classe Servidor 
    private static volatile Servidor instancia;

    public static Servidor getInstancia()
    {
        Servidor tmp = instancia;

        if(tmp != null) { return tmp; }

        synchronized (Servidor.class) {
            if(instancia == null){
                instancia = new Servidor();
            }
            return instancia;
        }
    }

    /* ======================================= */
    /*           GETTERS E SETTERS             */
    /* ======================================= */ 

    protected SecretKey getChaveAES(String cpf) { return chavesAES.get(cpf); }
    protected String getChaveVernam(String cpf) { return chavesVernam.get(cpf); }
    protected IvParameterSpec getVetorInit(String cpf) { return vetores_init.get(cpf); }
    protected String getChaveHMAC(String cpf) { return chaves_hmac.get(cpf); }
    
    protected void setVetorInit(String cpf, IvParameterSpec newVI) 
    {
        if(cpf.isBlank()){
            System.out.println("CPF inválido!");
            return;
        }
        if(newVI == null){
            System.out.println("Vetor de Inicialização está nulo!");
            return;
        }
        vetores_init.replace(cpf, newVI);
    }

    /* ======================================= */
    /*      ADICAO DE UM CPF NO SERVIDOR       */
    /* ======================================= */ 

    protected void addCPF(String cpf, String chave_hmac)
    {
        try {
            chavesAES.put(cpf, Cifrador.gerarChaveAES());
            chavesVernam.put(cpf, Cifrador.gerarChaveVernam());
            vetores_init.put(cpf, Cifrador.gerar_vetor_inicializacao());
            chaves_hmac.put(cpf, chave_hmac);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
    }
}