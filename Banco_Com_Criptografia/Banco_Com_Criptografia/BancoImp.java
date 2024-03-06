package Banco_Com_Criptografia;

import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class BancoImp implements Banco{
    private List<Cliente> contas = new ArrayList<Cliente>();
    /* Chave = CPF do usuário, Value = chave AES */
    private Map<String, SecretKey> chavesAES = new HashMap<String, SecretKey>();
    /* Chave = CPF do usuário, Value = chave Vernam */
    private Map<String, String> chavesVernam = new HashMap<String, String>();
    /* Chave = CPF do usuário, Value = vetor de inicializacao (temporario) */
    private Map<String, IvParameterSpec> vetores_init = new HashMap<String, IvParameterSpec>();

    /* ======================================= */
    /*                OPERACOES                */
    /* ======================================= */ 

    @Override
    public boolean autenticar(String cpf, String msg_cifrada, String tag_recebida) throws RemoteException
    {
        /* Decifra mensagem recebida */
        String mensagem = Cifrador.decifrar_mensagem(msg_cifrada, cpf);
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
        String mensagem = Cifrador.decifrar_mensagem(msg_cifrada, cpf);

        /* Quebra a mensagem para resgatar os dados */
        String [] dados = mensagem.split("|");

        /* Verifica se a conta ja esta cadastrada */
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente != null){
            return false;
        }

        /* Adiciona o cliente no Banco e seus dados no Servidor */
        contas.add(new Cliente(dados, false));
        addCPF(dados[1]);
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

    private String visualizar_perfil(String cpf)
    {
        Cliente cliente = buscar_por_cpf(cpf);

        return "Nome: " + cliente.getNome() + "\nNumero da conta: " + 
            cliente.getNumeroConta() + "\nCPF: " + cliente.getCpf() +
            "\nEndereço: " + cliente.getEndereco() + "\nTelefone: " +
            cliente.getTelefone(); 
    }

    /* ======================================= */
    /*           TROCA DE MENSAGENS            */
    /* ======================================= */ 

    /* Verifica a integridade da mensagem */
    public String receber_mensagem(String cpf, String msg_cripto, String tag_recebida) throws RemoteException
    {
        String chave = getChaveHMAC(cpf);
        if(Autenticador.autenticar_mensagem(msg_cripto, chave, tag_recebida)){
            String mensagem = Cifrador.decifrar_mensagem(msg_cripto, cpf);
            return enviar_mensagem(cpf, mensagem, chave);
        }
        return null;
    }
    
    public String enviar_mensagem(String cpf, String mensagem, String chave) throws RemoteException
    {
        // Gera resposta
        String resposta = definir_operacao(cpf, mensagem);
        // Cifra a resposta
        String cripto_res = Cifrador.cifrar_mensagem(resposta, cpf);
        // Gera a tag
        String tag = Autenticador.gerar_tag(cripto_res, chave);

        return cripto_res + "|" + tag;
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 
    
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
            
            case "perfil":
                return visualizar_perfil(cpf);
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
        return getChaveHMAC(cpf);
    }

    public SecretKey getChaveAES(String cpf) 
    { 
        SecretKey chave = chavesAES.get(cpf);
        if(chave == null){
            addCPF(cpf);
            return getChaveAES(cpf);
        }else{
            return chave;
        } 
    }

    public String getChaveVernam(String cpf) 
    { 
        String chave = chavesVernam.get(cpf); 
        if(chave == null){
            addCPF(cpf);
            return getChaveVernam(cpf);
        }else{
            return chave;
        } 
    }
    
    public IvParameterSpec getVetorInit(String cpf) 
    { 
        IvParameterSpec vi = vetores_init.get(cpf); 
        if(vi == null){
            addCPF(cpf);
            return getVetorInit(cpf);
        }else{
            return vi;
        } 
    }

    public String getChaveHMAC(String cpf) 
    { 
        return buscar_por_cpf(cpf).chave_hmac; 
    }
    
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

    protected void addCPF(String cpf)
    {
        /* Verifica se o cpf já foi cadastrado para inserir */
        if(chavesVernam.get(cpf) == null){
            chavesVernam.put(cpf, Cifrador.gerarChaveVernam());
        }
        if(chavesAES.get(cpf) == null){
            try {
                chavesAES.put(cpf, Cifrador.gerarChaveAES());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        if(vetores_init.get(cpf) == null){
            vetores_init.put(cpf, Cifrador.gerar_vetor_inicializacao());
        }
    }
}
