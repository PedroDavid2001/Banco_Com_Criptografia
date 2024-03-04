import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class BancoImp implements Banco{
    private List<Cliente> contas = null;
    private Servidor servidor = null;
    private Cifrador cifrador = null;

    private BancoImp(Servidor servidor)
    {
        contas = new ArrayList<Cliente>();
        if(servidor != null){
            this.servidor = servidor;
        }
        cifrador = Cifrador.getInstancia(servidor);
    }

    // Aplicacao de padrão Singleton para classe Banco 
    private static volatile BancoImp instancia;
    protected static BancoImp getInstancia(Servidor servidor)
    {
        BancoImp tmp = instancia;

        if(tmp != null) { return tmp; }

        synchronized (BancoImp.class) {
            if(instancia == null){
                instancia = new BancoImp(servidor);
            }
            return instancia;
        }
    }

    public void tela_menu()
    {
        System.out.println("=== SELECIONE UMA OPÇÃO ===");
        System.out.println("[1] - Login");
        System.out.println("[2] - Cadastrar");

    }

    /* ======================================= */
    /*                OPERACOES                */
    /* ======================================= */ 

    private boolean autenticar(String numero_conta, String senha)
    {
        Cliente cliente = buscar_por_numero(numero_conta);
        if(cliente == null){
            return false;
        }

        String senha_encontrada = cliente.getSenha();
        if(senha_encontrada.equals(senha)) { 
            return true; 
        }

        return false;
    }

    private void cadastrar() throws RemoteException
    {

    }

    private void saque() throws RemoteException
    {

    }

    private void deposito() throws RemoteException
    {

    }

    private void transferencia() throws RemoteException
    {
        
    }

    private void saldo() throws RemoteException
    {

    }

    private void poupanca(int meses) throws RemoteException
    {

    }

    private void renda_fixa(int meses) throws RemoteException
    {

    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    /* Verifica a integridade da mensagem */
    public String receber_mensagem(String cpf, String msg_cripto, String tag_recebida) throws RemoteException
    {
        String mensagem = cifrador.decifrar_mensagem(msg_cripto, cpf);
        String chave = servidor.getChaveHMAC(cpf);

        if(Autenticador.autenticar_mensagem(mensagem, chave, tag_recebida)){
            return definir_operacao(mensagem);
        }
        return null;
    }

    /* Tipos de mensagem:
    * > "autenticar|${numero_conta}|${senha}"
    * > "cadastrar"
    * > "saque|${valor}"
    * > "deposito|${valor}" 
    * > "transferencia|${valor}" 
    * > "saldo"
    * > "poupanca|${meses}"
    * > "renda_fixa|${meses}"
    */
    private String definir_operacao(String mensagem)
    {
        String [] operacao = mensagem.split("|");
        
        switch (operacao[0]) {
            case "autenticar":
                if(autenticar(operacao[1], operacao[2])){
                    return "Entrando no sistema. . .";
                }else{
                    return "Dados inválidos!";
                }
                
            default:
                break;
        }
    }

    private Cliente buscar_por_numero(String numero_conta)
    {
        for(Cliente c : contas) {
            if(c.getNumeroConta().equals(numero_conta)){
                return c;
            }
        }
        return null;
    }
}
