public class Main {
    private static final int PORTA = 50005;

    public static void config()
    {
        System.setProperty("java.rmi.server.hostname", "127.0.0.1");
        System.setProperty("java.security.policy", "java.policy");
    }

    public static void main(String[] args) {
        config();

        try {
            // Cria servidor
            Servidor servidor = Servidor.getInstancia();

            
        } catch (Exception e) {
            System.err.println("Servidor: " + e.getMessage());
            e.printStackTrace();
        }   
    }
}
