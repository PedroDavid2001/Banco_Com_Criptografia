import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/*
 Classe responsavel por controlar a geracao e distribuicao 
 de chaves, bem como realizar autenticacao nas mensagens 
 trocadas com base nas chaves. 
*/
public final class Servidor {

    // Aplicacao de padrão Singleton para classe Servidor 
    private static volatile Servidor instancia;

    /* Chave = CPF do usuário, Value = chave AES */
    private Map<String, SecretKey> chavesAES = null;
    /* Chave = CPF do usuário, Value = chave Vernam */
    private Map<String, String> chavesVernam = null;
    /* Chave = CPF do usuário, Value = vetor de inicializacao (temporario) */
    private Map<String, IvParameterSpec> vetores_init = null;

    private Servidor()
    {
        chavesAES = new HashMap<String, SecretKey>();
        chavesVernam = new HashMap<String, String>();
        vetores_init = new HashMap<String, IvParameterSpec>();
    }

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

    public SecretKey getChaveAES(String cpf) { return chavesAES.get(cpf); }
    public String getChaveVernam(String cpf) { return chavesVernam.get(cpf); }
    public IvParameterSpec getVetorInit(String cpf) { return vetores_init.get(cpf); }
    
    public void setVetorInit(String cpf, IvParameterSpec newVI) 
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

    public void addCPF(String cpf)
    {
        try {
            chavesAES.put(cpf, Cifrador.gerarChaveAES());
            chavesVernam.put(cpf, Cifrador.gerarChaveVernam());
            vetores_init.put(cpf, Cifrador.gerar_vetor_inicializacao());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
    }
}