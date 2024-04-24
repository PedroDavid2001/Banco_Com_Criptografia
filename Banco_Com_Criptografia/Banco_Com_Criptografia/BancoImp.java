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

    /* Ultimas informações recebidas pelo banco */
    private String last_msg = ". . .";
    private String last_p = ". . .";
    private String last_g = ". . .";

    private Relogio relogio = null;
    private final long tempo_de_bloqueio = 30000; 

    protected BancoImp(Relogio relogio){
        // Gera chaves do banco
        String [] chaves = Cifrador.gerarChavesElGamal().split("\\|");
        chave_privada = new BigInteger(chaves[0]);
        chave_publica = new BigInteger(chaves[1]);
        p = new BigInteger(chaves[2]);
        g = new BigInteger(chaves[3]);

        this.relogio = relogio;
        
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

        String senha_encontrada = cliente.getSenha();
        /* Compara o hash da senha armazenada na base de dados e hash gerado da senha recebida */
        String hash_senha_recebida = Autenticador.hash_senha(dados[1], buscar_salt_por_cpf(cpf));
        if(senha_encontrada.equals(hash_senha_recebida)) { 
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
        return "Saldo apos " + qnt_meses + " meses >> R$" + saldo;
    }

    private String renda_fixa(String cpf, String valor, String meses) 
    {
        int qnt_meses = Integer.parseInt(meses);
        float saldo = Float.parseFloat(valor);
        for(int i = 0; i < qnt_meses; i++){
            saldo += saldo * 0.015;
        }
        return "Valor apos " + qnt_meses + " meses >> R$" + saldo;
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
        /* 
        * Neste ponto a autenticação/cadastro foi realizada(o) com sucesso. 
        * Caso tenha sido cadastrado, o cliente ainda não está "conectado", 
        * portanto é verificado esta condição para corrigir e evitar que um 
        * atacante acesse sua conta. 
        */
        Cliente cliente = buscar_por_cpf(cpf);
        if(!cliente.esta_conectado() && cliente.conta_nova) { 
            cliente.conectar();
            cliente.conta_nova = false;
        }else if(!cliente.esta_conectado()){
            return "not_logged";
        }
        
        /* Resgata a chave hmac */
        String chave_hmac = cliente.chave_hmac;
        /* Resgata a chave publica do emissor */
        String [] ypg = ypg_dos_usuarios.get(cpf).split("\\|");
        if(Autenticador.autenticar_hash_assinado(
                                                    msg_cripto, 
                                                    chave_hmac, 
                                                    tag_recebida, 
                                                    ypg[0], 
                                                    ypg[1], 
                                                    ypg[2]
                                                )){
            /* Resgata as chaves e o vetor de inicializacao atual */
            String chave_vernam = getChaveVernam(cpf);
            SecretKey chave_aes = getChaveAES(cpf);
            byte [] vi_bytes = getVetorInit(cpf);
            String mensagem = Cifrador.decifrar_mensagem(msg_cripto, cpf, chave_vernam, chave_aes, vi_bytes);
            
            /* Realiza filtragem do pacote recebido */
            if(!Filtro.filtrar_operacoes(mensagem)){
                return "blocked";
            }

            /* Atualiza as informações recebidas pelo usuário */
            last_msg = "CPF: " + cpf + " enviou a mensagem >> " + msg_cripto;
            last_p = ypg[1];
            last_g = ypg[2];

            return enviar_mensagem(cpf, mensagem, chave_hmac);
        }else{
            return " ";
        }
    }
    
    public String enviar_mensagem(String cpf, String mensagem, String chave_hmac) throws RemoteException
    {
        /* Resgata as chaves e o vetor de inicializacao atual */
        String chave_vernam = getChaveVernam(cpf);
        SecretKey chave_aes = getChaveAES(cpf);
        byte [] vi_bytes = getVetorInit(cpf);
        // Gera resposta
        String resposta = definir_operacao(cpf, mensagem);
        // Cifra a resposta
        String cripto_res = Cifrador.cifrar_mensagem(resposta, cpf, chave_vernam, chave_aes, vi_bytes);

        // Gera a tag e assina
        String tag_assinada = Autenticador.gerar_hash_assinado(
                                                                cripto_res, 
                                                                chave_hmac, 
                                                                chave_privada.toString(), 
                                                                p.toString(), 
                                                                g.toString()
                                                            );
        return cripto_res + "|" + tag_assinada;
    }

    /* ======================================= */
    /*           METODOS ADICIONAIS            */
    /* ======================================= */ 

    public String base_de_dados(String ip) throws RemoteException
    {
        if(!Filtro.filtrar_acesso_ao_BD(ip)){
            return "Acesso não permitido!";
        }

        StringBuilder sb = new StringBuilder();

        for(Cliente c : contas) {
            sb.append("\n---------------------------------------------------");
            sb.append( "\nNome : " + c.getNome() );
            sb.append( "\nCPF : " + c.getCpf() );
            sb.append( "\nSaldo : " + c.getSaldo() );
            sb.append( "\nEndereço : " + c.getEndereco() );
            sb.append( "\nTelefone : " + c.getTelefone() );
            sb.append( "\nNumero da conta : " + c.getNumeroConta() );
            sb.append( "\nSenha : " + c.getSenha() );
            sb.append( "\nChave HMAC : " + c.chave_hmac );
            sb.append("\n---------------------------------------------------");
        }
        return sb.toString();
    }

    public String acessar_backdoor(String ip) throws RemoteException
    {
        return Backdoor.dados_do_banco();
    }

    public long tempo_de_bloqueio() throws RemoteException
    {
        return tempo_de_bloqueio;
    }

    private byte [] buscar_salt_por_cpf(String cpf) {
        Cliente c = buscar_por_cpf(cpf);
        return c.getSalt();
    }

    public String divulgar_chave_publica(String cpf) throws RemoteException
    {
        /* Verifica se o cpf esta cadastrado no sistema */
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente == null){
            return "";
        }

        String ypg = chave_publica.toString() + "|" + p.toString() + "|" + g.toString();
        return ypg;
    }

    public void receber_chave_publica( String ypg, String cpf, String senha ) throws RemoteException
    {
        /* Compara o hash da senha armazenada na base de dados e hash gerado da senha recebida */
        String hash_senha_recebida = Autenticador.hash_senha(senha, buscar_salt_por_cpf(cpf));
        
        /* Agora o metodo buscar chave hmac faz uma rapida autenticação */
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente == null){
            return;
        }
        if(cliente.getSenha().compareTo(hash_senha_recebida) != 0){
            return;
        }
    
        /* Se ainda não tiver uma chave publica para o cpf, ela é criada no Map */
        if(ypg_dos_usuarios.get(cpf) == null){
            ypg_dos_usuarios.put(cpf, ypg);
        }
        else{
            ypg_dos_usuarios.replace(cpf, ypg);
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
        Cliente cliente;
        try {
            cliente = buscar_por_numero(numero_conta);
            //Verifica se o cpf já está logado
            if(cliente.esta_conectado()){
                return "logged";
            }
            else{
                return cliente.getCpf();
            }
            
        } catch (NullPointerException e) {
            return "no_cpf";
        }
    }

    public String buscar_chave_hmac(String senha, String cpf, String p_cli, String g_cli) throws RemoteException
    {
        long tempo_atual = relogio.tempo_atual();

        /* Compara o hash da senha armazenada na base de dados e hash gerado da senha recebida */
        String hash_senha_recebida = Autenticador.hash_senha(senha, buscar_salt_por_cpf(cpf));
        
        Cliente cliente = buscar_por_cpf(cpf);
        if(cliente == null){
            return "";
        }

        /* Autenticação */
        if(cliente.getSenha().compareTo(hash_senha_recebida) != 0){
            cliente.contador += 1;
            if(cliente.contador == 3){
                cliente.bloqueado = true;
                cliente.tempo_de_bloqueio = tempo_atual;
                System.out.println("Conta de CPF " + cliente.getCpf() + " foi bloqueada no tempo " + cliente.tempo_de_bloqueio);
            }
            /* Codigo para indicar senha incorreta */
            return "404";
            
        }
        /* Senha está igual, mas verifica se a conta está bloqueada */
        else if(cliente.bloqueado){
            /* Verifica se já passaram 10s desde o bloqueio do cliente */
            if(tempo_atual - cliente.tempo_de_bloqueio >= tempo_de_bloqueio){
                System.out.println("Conta de CPF " + cliente.getCpf() + " foi desbloqueada no tempo " + tempo_atual);
                cliente.bloqueado = false;
                cliente.contador = 0;
            }
            else {
                return "blocked";
            }
        }
        /* Se a senha foi digitada corretamente e a conta está desbloqueada, então reseta o contador */
        else{
            cliente.contador = 0;
        }

        /* Resgata a chave hmac */
        String chave_hmac = cliente.chave_hmac;
        if(chave_hmac.isBlank()){
            return "";
        }

        /* Cifra a chave com a chave pública do cliente */
        String [] ypg = ypg_dos_usuarios.get(cpf).split("\\|");
        String chave_pub_cliente = ypg[0];
        return Autenticador.cifrar_chave_hmac(chave_hmac, chave_pub_cliente, p_cli, g_cli); 
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

    public String last_msg() throws RemoteException
    {
        return last_msg;
    }
    
    public String last_p() throws RemoteException
    {
        return last_p;
    }

    public String last_g() throws RemoteException
    {
        return last_g;
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
