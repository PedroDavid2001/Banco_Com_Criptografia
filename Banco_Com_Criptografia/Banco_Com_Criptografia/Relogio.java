package Banco_Com_Criptografia;

public class Relogio extends Thread {
    private long inicio;
    private long tempo_atual;

    public void run() {
        inicio = System.currentTimeMillis();

        while (true) {
            tempo_atual = System.currentTimeMillis() - inicio;
            try {
                /* Espera 1 segundo antes de atualizar o tempo */
                Thread.sleep(1000); 
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    protected long tempo_atual() {
        return tempo_atual;
    }

}
