package Banco_Com_Criptografia;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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
    /* Chave = CPF do usuário, Value = chave publica|p|g */
    private Map<String, String> ypg_dos_usuarios = new HashMap<String, String>();

    /* Chaves assimetricas do banco */
    private final BigInteger chave_privada;
    private final BigInteger chave_publica;
    private final BigInteger p;
    private final BigInteger g;

    protected BancoImp(){
        // Gera chaves do banco
        String [] chaves = Cifrador.gerarChavesElGamal().split("\\|");
        chave_privada = new BigInteger(chaves[0]);
        chave_publica = new BigInteger(chaves[1]);
        p = new BigInteger(chaves[2]);
        g = new BigInteger(chaves[3]);
        System.out.println("Chave privada do banco: " + chave_privada.toString());
        System.out.println("Chave publica do banco: " + chave_publica.toString());
        System.out.println("p: " + p.toString());
        System.out.println("g: " + g.toString());

        // Carrega clientes
        try{
            ler_arquivo();
        }catch(IOException e){
            e.printStackTrace();
        }   
    }

    /* ======================================= */
    /*                OPERACOES                */
    /* ======================================= */ 

    @Override
    public boolean autenticar(String cpf, String msg_cifrada, String tag_recebida) throws RemoteException
    {
        /* Resgata as chaves e o vetor de inicializacao atual */
        String chave_vernam = getChaveVernam(cpf);
        SecretKey chave_aes = getChaveAES(cpf);
        byte [] vi_bytes = getVetorInit(cpf);
        
        /* Decifra mensagem recebida */
        String mensagem = Cifrador.decifrar_mensagem(msg_cifrada, cpf, chave_vernam, chave_aes, vi_bytes);
        String [] dados = mensagem.split("\\|");

        /* Verifica a integridade da mensagem */
        if(!Autenticador.autenticar_mensagem(msg_cifrada, buscar_por_cpf(cpf).chave_hmac, tag_recebida)){
            return false;
        }

        Cliente cliente = buscar_por_numero(dados[0]);
        if(cliente == null){
            return false;
        }

        /* Se ja estiver conectado, nao permite outra conexao */
        if(verificar_conexao(cpf)){
            return false;
        }

        String senha_encontrada = cliente.getSenha();
        if(senha_encontrada.equals(dados[1])) { 
            /* Conecta o cliente e abre o acesso */
            cliente.conectar();
            return true; 
        }

        return false;
    }

    @Override
    public boolean cadastrar(String cpf, String msg_cifrada) throws RemoteException
    {
        /* Resgata as chaves e o vetor de inicializacao atual */
        String chave_vernam = getChaveVernam(cpf);
        SecretKey chave_aes = getChaveAES(cpf);
        byte [] vi_bytes = getVetorInit(cpf);

        /* Decifra mensagem recebida */
        String mensagem = Cifrador.decifrar_mensagem(msg_cifrada, cpf, chave_vernam, chave_aes, vi_bytes);
        /* Quebra a mensagem para resgatar os dados */
        String [] dados = mensagem.split("\\|");
        
        /* Verifica se a conta ja esta cadastrada */
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente != null){
            return false;
        }

        /* Adiciona o cliente no Banco e seus dados no Servidor */
        contas.add(new Cliente(dados, false));
        /* Conecta o cliente */
        buscar_por_cpf(dados[1]).conectar();
        /* Gera as chaves e o primeiro vetor de inicializacao */
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
        String chave = buscar_por_cpf(cpf).chave_hmac;
        if(Autenticador.autenticar_mensagem(msg_cripto, chave, tag_recebida)){
            /* Resgata as chaves e o vetor de inicializacao atual */
            String chave_vernam = getChaveVernam(cpf);
            SecretKey chave_aes = getChaveAES(cpf);
            byte [] vi_bytes = getVetorInit(cpf);
            String mensagem = Cifrador.decifrar_mensagem(msg_cripto, cpf, chave_vernam, chave_aes, vi_bytes);
            return enviar_mensagem(cpf, mensagem, chave);
        }else{
            return " ";
        }
    }
    
    public String enviar_mensagem(String cpf, String mensagem, String chave) throws RemoteException
    {
        /* Resgata as chaves e o vetor de inicializacao atual */
        String chave_vernam = getChaveVernam(cpf);
        SecretKey chave_aes = getChaveAES(cpf);
        byte [] vi_bytes = getVetorInit(cpf);
        // Gera resposta
        String resposta = definir_operacao(cpf, mensagem);
        // Cifra a resposta
        String cripto_res = Cifrador.cifrar_mensagem(resposta, cpf, chave_vernam, chave_aes, vi_bytes);
        // Gera a tag
        String tag = Autenticador.gerar_tag(cripto_res, chave);

        return cripto_res + "|" + tag;
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    public String divulgar_chave_publica(String cpf) throws RemoteException
    {
        String msg = chave_publica.toString() + "|" + p.toString() + "|" + g.toString();
        
        /* Resgata as chaves e o vetor de inicializacao atual */
        String chave_vernam = getChaveVernam(cpf);
        SecretKey chave_aes = getChaveAES(cpf);
        byte [] vi_bytes = getVetorInit(cpf);
        String chave_hmac = buscar_por_cpf(cpf).chave_hmac;

        // Cifra a resposta e gera a tag
        String cripto_res = Cifrador.cifrar_mensagem(msg, cpf, chave_vernam, chave_aes, vi_bytes);
        String tag = Autenticador.gerar_tag(cripto_res, chave_hmac);

        return cripto_res + "|" + tag;
    }

    public void receber_chave_publica(String ypg_cifrado) throws RemoteException
    {
        String chave = buscar_por_cpf(cpf).chave_hmac;
        if(Autenticador.autenticar_mensagem(msg_cripto, chave, tag_recebida)) {
            /* Resgata as chaves e o vetor de inicializacao atual */
            String chave_vernam = getChaveVernam(cpf);
            SecretKey chave_aes = getChaveAES(cpf);
            byte [] vi_bytes = getVetorInit(cpf);
            
            /* Mensagem esperada é composta pela chave publica, "p" e "g" do usuario */
            String ypg = Cifrador.decifrar_mensagem(msg_cripto, cpf, chave_vernam, chave_aes, vi_bytes);
            
            /*----------------------------------------------------------------- */
            /* Trecho usado para depuração */
            String [] dados = ypg.split("\\|");
            System.out.println("Chave publica do cpf: " + cpf + " = " + dados[0]);
            System.out.println("\"p\" do cpf: " + cpf + " = " + dados[1]);
            System.out.println("\"g\" do cpf: " + cpf + " = " + dados[2]);
            /*----------------------------------------------------------------- */
            
            /* Se ainda não tiver uma chave publica para o cpf, ela é criada no Map */
            if(ypg_dos_usuarios.get(cpf) == null){
                ypg_dos_usuarios.put(cpf, ypg);
            }
            else{
                ypg_dos_usuarios.replace(cpf, ypg);
            }
            
        }
    }
    
    private String definir_operacao(String cpf, String mensagem)
    {
        String [] operacao = mensagem.split("\\|");
        
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
            case "sair":
                buscar_por_cpf(cpf).desconectar();
                System.out.println("Cliente com CPF:" + cpf + " desconectado." );
                
                try{
                    escrever_arquivo();
                }catch(IOException e){
                    e.printStackTrace();
                }
                return " ";
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
        String chave_hmac = buscar_por_cpf(cpf).chave_hmac;
        if(chave_hmac == null || chave_hmac.isBlank()){
            return "";
        }
        /* Cifra a chave com a chave pública do cliente */
        String [] ypg = ypg_dos_usuarios.get(cpf).split("\\|");
        String chave_pub_cliente = ypg[0];
        return Autenticador.cifrar_chave_hmac(chave_hmac, chave_pub_cliente, p.toString(), g.toString()); 
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

    public byte [] getVetorInit(String cpf) 
    {
        IvParameterSpec vi = vetores_init.get(cpf); 

        if(vi == null){
            addCPF(cpf);
            return getVetorInit(cpf);
        }else{
            return vi.getIV();
        } 
    }

    public void setVetorInit(String cpf) 
    {
        IvParameterSpec vi = gerar_vetor_inicializacao();

        if(cpf.isBlank()){
            System.out.println("CPF inválido!");
            return;
        }
        vetores_init.replace(cpf, vi);
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
            vetores_init.put(cpf, gerar_vetor_inicializacao());
        }
    }

    private boolean verificar_conexao(String cpf) throws RemoteException
    {
        return buscar_por_cpf(cpf).esta_conectado();
    }

    /* ======================================= */
    /*    GERACAO DE VETOR DE INICIALIZACAO    */
    /* ======================================= */ 

    public static IvParameterSpec gerar_vetor_inicializacao()
    {
        byte [] vi = new byte[16];
        new SecureRandom().nextBytes(vi);
        return new IvParameterSpec(vi);
    }

    /* ======================================= */
    /*       LEITURA E ESCRITA DE ARQUIVO      */
    /* ======================================= */ 

    private void escrever_arquivo() throws IOException{
        StringBuilder texto = new StringBuilder();

        if(contas.size() == 0){
            return;
        }

        for(Cliente c : contas){
            texto.append(c.toString() + ";");
        }
        
		BufferedWriter bWriter = new BufferedWriter( new FileWriter("Banco_Com_Criptografia/Banco_Com_Criptografia/Contas.txt") );
        bWriter.append(texto.toString());
		bWriter.close();
	}

    private void ler_arquivo() throws IOException 
    {
        BufferedReader bReader = new BufferedReader( new FileReader("Banco_Com_Criptografia/Banco_Com_Criptografia/Contas.txt") );
        String texto = bReader.readLine();
        /* Verifica se o arquivo estava vazio */
        if(texto == null || texto.isBlank()){
            bReader.close();
            return;
        }

        String [] clientes = texto.split(";");

        for(String c : clientes){
            contas.add(new Cliente(c.split("\\|"), true));
        }

        bReader.close();
    }

}
