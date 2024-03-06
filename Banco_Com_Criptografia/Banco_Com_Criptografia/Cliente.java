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

    private String DIGITOS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    /* Chave protected para ser acessada somente no package e final para ser read-only. */
    protected final String chave_hmac;

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
            chave_hmac = dados[6];
        } 
        else {
            StringBuilder chave = new StringBuilder();
            for(int i = 0; i < 15; i++){
                int index = new SecureRandom().nextInt(DIGITOS.length());
                chave.append(DIGITOS.charAt(index));
            }
            this.chave_hmac = chave.toString();
            
            setSaldo(0.0f);
            setNumeroConta();
    
            setNome(dados[0]);
            setCpf(dados[1]);
            setEndereco(dados[2]);
            setTelefone(dados[3]);
            setSenha(dados[4]);
        }

    }

    public String getNome() {
        return nome;
    }

    protected void setNome(String nome) {
        if(nome.isBlank()){
            System.out.println("Nome inválido!");
            return;
        }
        this.nome = nome;
    }

    public String getCpf() {
        return cpf;
    }

    protected void setCpf(String cpf) {
        if(cpf.isBlank()){
            System.out.println("CPF inválido!");
            return;
        }
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
                System.out.println("Saldo insuficiente para realizar a operação!");
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
        if(endereco.isBlank()){
            System.out.println("Endereço inválido!");
            return;
        }
        this.endereco = endereco;
    }

    protected String getTelefone() {
        return telefone;
    }

    protected void setTelefone(String telefone) {
        if(telefone.isBlank()){
            System.out.println("Telefone inválido!");
            return;
        }
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
            gerador.append((char) new SecureRandom().nextInt(10));
        }
        gerador.append('-');
        gerador.append((char) new SecureRandom().nextInt(10));
        this.numero_conta = gerador.toString();
    }

    protected String getSenha() {
        return senha;
    }

    protected void setSenha(String senha) {
        if(senha.isBlank()){
            System.out.println("Senha inválida!");
            return;
        }
        this.senha = senha;
    }

    @Override
    public String toString()
    {
        return getNome() + "|" + getCpf() + "|"+ getSaldo() + "|" + getEndereco() + 
                "|" + getTelefone()  + "|" + getNumeroConta() + "|" + getSenha() + "|" + chave_hmac;
    }
}