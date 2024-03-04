import java.util.ArrayList;
import java.util.List;

public class Banco {
    private List<Cliente> contas = null;
    private Servidor servidor = null;

    private Banco(Servidor servidor)
    {
        contas = new ArrayList<Cliente>();
        if(servidor != null){
            this.servidor = servidor;
        }
    }

    // Aplicacao de padrão Singleton para classe Banco 
    private static volatile Banco instancia;

    public static Banco getInstancia(Servidor servidor)
    {
        Banco tmp = instancia;

        if(tmp != null) { return tmp; }

        synchronized (Banco.class) {
            if(instancia == null){
                instancia = new Banco(servidor);
            }
            return instancia;
        }
    }
}
