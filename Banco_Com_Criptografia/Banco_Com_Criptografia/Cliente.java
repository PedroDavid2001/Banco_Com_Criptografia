package Banco_Com_Criptografia;

import java.security.SecureRandom;

public class Cliente {
    private String nome = null;   
    private String cpf = null;
    private float saldo;
    private String endereco = null;
    private String telefone = null;
    private String numero_conta;
    private String senha = null;
    private byte [] salt;
    private boolean conectado;

    protected boolean bloqueado = false;
    /* 
     * Contador utilizado para determinar se o usuario gastou todas as 
     * tentativas e também para calcular o tempo restante de bloqueio 
     * da conta
     */
    protected int contador = 0;
    /* Estampa de tempo do momento em que foi bloqueado */
    protected long tempo_de_bloqueio;

    /* Chave protected para ser acessada somente no package e final para ser read-only. */
    protected final String chave_hmac;

    /* 
     * boolean utilizado para informar se a conta acabou de ser cadastrada.
     * 
     *  O usuario que acabou de ser cadastrado só é considerado conectado 
     * após a primeira solicitação de operação. O usuário é conectado no 
     * momento em que realiza a primeira operação e esta variavel é setada 
     * para false. 
     *  Outros usuários que tentarem realizar uma operação sem ter sido 
     * autenticado, não conseguirão realizar operação.
     */
    protected boolean conta_nova;

    protected Cliente( String [] dados, boolean carregar_de_arquivo)
    {
        /* 
         Quando carregando de um arquivo, o array 
         'dados' deverá conter todas as informações 
        */
        if(carregar_de_arquivo) {
            setNome(dados[0]);
            setCpf(dados[1]);
            setSaldo(dados[2]);
            setEndereco(dados[3]);
            setTelefone(dados[4]);
            setNumeroConta(dados[5]);
            setSenha(dados[6]);
            chave_hmac = dados[7];
            setSalt(Autenticador.string_to_byte_arr(dados[8]));
            conta_nova = false;
            conectado = false;
        } 
        else {
            StringBuilder chave = new StringBuilder();
            for(int i = 0; i < 15; i++){
                chave.append(new SecureRandom().nextInt(10));
            }
            this.chave_hmac = chave.toString();
            
            setSaldo(0.0f);
            setNumeroConta();
    
            setNome(dados[0]);
            setCpf(dados[1]);
            setEndereco(dados[2]);
            setTelefone(dados[3]);
            /* 
            * Gera salt e hash da senha para armazenar este 
            * valor na base de dados ao invés da senha "crua"
            */
            setSalt(Autenticador.gerar_salt());
            setSenha(Autenticador.hash_senha(dados[4], salt));
            conta_nova = true;
            conectado = false;
        }
    }

    public String getNome() {
        return nome;
    }

    protected void setNome(String nome) {
        this.nome = nome;
    }

    public String getCpf() {
        return cpf;
    }

    protected void setCpf(String cpf) {
        this.cpf = cpf;
    }

    public float getSaldo() {
        return saldo;
    }

    public void setSaldo(String saldo) {
        if(!saldo.isBlank()){
            this.saldo = Float.parseFloat(saldo);
        }
    }

    protected boolean setSaldo(float saldo) {
        /* 
         O parametro de setSaldo nao substitui o 
         valor do atributo 'saldo', mas altera ele.
        */ 
        /*
         Deve ser realizado um teste para garantir 
         que, caso o valor passado no argumento 
         seja negativo, seu modulo deve ser menor 
         ou igual ao valor no atributo 'saldo'. 
        */ 
        if(saldo < 0 ){
            if((saldo * -1.0f) > this.saldo){
                return false;
            }
        }
        this.saldo += saldo;
        return true;
    }

    protected String getEndereco() {
        return endereco;
    }

    protected void setEndereco(String endereco) {
        this.endereco = endereco;
    }

    protected String getTelefone() {
        return telefone;
    }

    protected void setTelefone(String telefone) {
        this.telefone = telefone;
    }

    protected String getNumeroConta() {
        return numero_conta;
    }

    protected void setNumeroConta(String numero_conta)
    {
        this.numero_conta = numero_conta;
    }

    /* Numero da conta gerado aleatoriamente */
    private void setNumeroConta() {
        StringBuilder gerador = new StringBuilder();
        for(int i = 0; i < 7; i++){
            gerador.append(new SecureRandom().nextInt(10));
        }
        gerador.append('-');
        gerador.append(new SecureRandom().nextInt(10));
        this.numero_conta = gerador.toString();
    }

    protected String getSenha() {
        return senha;
    }

    protected void setSenha(String senha) {
        this.senha = senha;
    }

    protected byte [] getSalt() {
        return salt;
    }

    protected void setSalt(byte [] salt) {
        this.salt = salt;
    }

    public boolean esta_conectado() {
        return conectado;
    }

    public void conectar() {
        System.out.println("Cliente com CPF:" + cpf + " conectado." );
        conectado = true;
    }

    public void desconectar() {
        System.out.println("Cliente com CPF:" + cpf + " desconectado." );
        conectado = false;
    }

    @Override
    public String toString()
    {
        return getNome() + "|" + getCpf() + "|"+ getSaldo() + "|" + getEndereco() + 
                "|" + getTelefone()  + "|" + getNumeroConta() + "|" + getSenha() + 
                "|" + chave_hmac + "|" + Autenticador.byte_arr_to_string(salt);
    }
}