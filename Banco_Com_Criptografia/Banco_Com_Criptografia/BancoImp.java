package Banco_Com_Criptografia;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

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

    /* ======================================= */
    /*                OPERACOES                */
    /* ======================================= */ 

    @Override
    public boolean autenticar(String cpf, String msg_cifrada, String tag_recebida) throws RemoteException
    {
        /* Decifra mensagem recebida */
        String mensagem = cifrador.decifrar_mensagem(msg_cifrada, cpf);
        String [] dados = mensagem.split("|");

        /* Verifica a integridade da mensagem */
        if(!Autenticador.autenticar_mensagem(msg_cifrada, buscar_chave_hmac(cpf), tag_recebida)){
            return false;
        }

        Cliente cliente = buscar_por_numero(dados[0]);
        if(cliente == null){
            return false;
        }

        String senha_encontrada = cliente.getSenha();
        if(senha_encontrada.equals(dados[1])) { 
            return true; 
        }

        return false;
    }

    @Override
    public boolean cadastrar(String cpf, String msg_cifrada) throws RemoteException
    {
        /* Decifra mensagem recebida */
        String mensagem = cifrador.decifrar_mensagem(msg_cifrada, cpf);

        /* Quebra a mensagem para resgatar os dados */
        String [] dados = mensagem.split("|");

        /* Verifica se a conta ja esta cadastrada */
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente != null){
            return false;
        }

        /* Adiciona o cliente no Banco e seus dados no Servidor */
        contas.add(new Cliente(dados));
        servidor.addCPF(dados[1], buscar_por_cpf(dados[1]).chave_hmac);
        return true;
    }

    private boolean saque(String cpf, String valor) 
    {
        Cliente cliente = buscar_por_cpf(cpf);
        float saque = Float.parseFloat(valor);
        return cliente.setSaldo(-1.0f * saque);
    }

    private void deposito(String cpf, String valor) 
    {
        Cliente cliente = buscar_por_cpf(cpf);
        float saque = Float.parseFloat(valor);
        cliente.setSaldo(saque);
    }

    private boolean transferencia(String cpf, String valor, String numero_destino) 
    {
        Cliente cliente = buscar_por_cpf(cpf);
        float saque = Float.parseFloat(valor);

        if(cliente.setSaldo(-1.0f * saque)){
            Cliente destino = buscar_por_numero(numero_destino);
            destino.setSaldo(saque);
            return true;
        } else{
            return false;
        }
    }

    private String saldo(String cpf) 
    {
        float saldo = buscar_por_cpf(cpf).getSaldo();
        return "Saldo atual >> R$" + saldo;
    }

    private String poupanca(String cpf, String meses) 
    {
        int qnt_meses = Integer.parseInt(meses);
        float saldo = buscar_por_cpf(cpf).getSaldo();
        for(int i = 0; i < qnt_meses; i++){
            saldo += saldo * 0.005;
        }
        return "Saldo apos " + qnt_meses + " >> R$" + saldo;
    }

    private String renda_fixa(String cpf, String valor, String meses) 
    {
        int qnt_meses = Integer.parseInt(meses);
        float saldo = Float.parseFloat(valor);
        for(int i = 0; i < qnt_meses; i++){
            saldo += saldo * 0.015;
        }
        return "Valor apos " + qnt_meses + " >> R$" + saldo;
    }

    /* ======================================= */
    /*           TROCA DE MENSAGENS            */
    /* ======================================= */ 

    /* Verifica a integridade da mensagem */
    public String receber_mensagem(String cpf, String msg_cripto, String tag_recebida) throws RemoteException
    {
        String chave = servidor.getChaveHMAC(cpf);
        if(Autenticador.autenticar_mensagem(msg_cripto, chave, tag_recebida)){
            String mensagem = cifrador.decifrar_mensagem(msg_cripto, cpf);
            return enviar_mensagem(cpf, mensagem, chave);
        }
        return null;
    }
    
    public String enviar_mensagem(String cpf, String mensagem, String chave) throws RemoteException
    {
        // Gera resposta
        String resposta = definir_operacao(cpf, mensagem);
        // Cifra a resposta
        String cripto_res = cifrador.cifrar_mensagem(resposta, cpf);
        // Gera a tag
        String tag = Autenticador.gerar_tag(cripto_res, chave);

        return cripto_res + "|" + tag;
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 
    
    /* Tipos de mensagem:
    * > "cadastrar"
    * > "saque|${valor}"
    * > "deposito|${valor}" 
    * > "transferencia|${valor}|${numero_conta(destino)}" 
    * > "saldo"
    * > "poupanca|${meses}"
    * > "renda_fixa|${valor}|${meses}"
    */
    private String definir_operacao(String cpf, String mensagem)
    {
        String [] operacao = mensagem.split("|");
        
        switch (operacao[0]) {
            case "saque":
                if(saque(cpf, operacao[1])){
                    return "Saque realizado com sucesso!";
                }else{
                    return "Saldo insuficiente!";
                }

            case "deposito":
                deposito(cpf, operacao[1]);
                return "Deposito realizado com sucesso!";

            case "transferencia":
                if(transferencia(cpf, operacao[1], operacao[2])){
                    return "Transferencia realizada com sucesso!";
                }else{
                    return "Saldo insuficiente!";
                }

            case "saldo":
                return saldo(cpf);

            case "poupanca":
                return poupanca(cpf, operacao[1]);

            case "renda_fixa":
                return renda_fixa(cpf, operacao[1], operacao[2]);

            default:
                return "Operacao invalida!";
 
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

    private Cliente buscar_por_cpf(String cpf)
    {
        for(Cliente c : contas) {
            if(c.getCpf().equals(cpf)){
                return c;
            }
        }
        return null;
    }

    public String buscar_cpf_na_autenticacao(String numero_conta) throws RemoteException
    {
        return buscar_por_numero(numero_conta).getCpf();
    }

    public String buscar_chave_hmac(String cpf) throws RemoteException
    {
        return servidor.getChaveHMAC(cpf);
    }
}
