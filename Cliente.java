import java.util.Random;

public class Cliente {
    private String nome;   
    private String cpf;
    private float saldo;
    private String endereco;
    private String telefone;
    private String numero_conta;

    public String getNome() {
        return nome;
    }
    public void setNome(String nome) {
        this.nome = nome;
    }
    public String getCpf() {
        return cpf;
    }
    public void setCpf(String cpf) {
        this.cpf = cpf;
    }
    public float getSaldo() {
        return saldo;
    }

    public void setSaldo(float saldo) {
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
                return;
            }
        }
        this.saldo += saldo;
    }

    public String getEndereco() {
        return endereco;
    }
    public void setEndereco(String endereco) {
        this.endereco = endereco;
    }
    public String getTelefone() {
        return telefone;
    }
    public void setTelefone(String telefone) {
        this.telefone = telefone;
    }

    public String getNumero_conta() {
        return numero_conta;
    }

    /* Numero da conta gerado aleatoriamente */
    public void setNumero_conta() {
        StringBuilder gerador = new StringBuilder();
        for(int i = 0; i < 7; i++){
            gerador.append((char) new Random().nextInt(10));
        }
        gerador.append('-');
        gerador.append((char) new Random().nextInt(10));
        this.numero_conta = gerador.toString();
    }
}