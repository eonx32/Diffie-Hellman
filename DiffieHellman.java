/**
 *
 *  Diffie_Hellman to method to exchange key between
 *  a pair of users. A shared key will be generated for
 *  encryption and decryption.
 *  
 *  Create two instance of this Programm in different terminals
 *  using command :
 *
 *  "java DiffieHellman port1 port2 prime primitiveroot"
 *  
 *  Send messages from one terminal to another.
 *  The messages will be encrypted using the shared key generated.
 *
 *  @author eonx_32
 *
 */

import java.util.*;
import java.io.*;
import java.net.*;

class DiffieHellman
{
    private long prime;
    private long primitiveRoot;
    private long myChoosenNumber;
    private long publicKey;
    private long sharedKey;
    private static final String DELIMITER = ":";
    private static final String PUBLICKEY = "PublicKey";
    private static final String MESSAGE = "Message";
    private DataEncryptionStandard des;
    
    DiffieHellman(long prime,long primitiveRoot,int portOfSender,int portOfReceiver)
    {
        this.prime = prime;
        this.primitiveRoot = primitiveRoot;
        
        Random rand = new Random();
        //Generate a secret integer between 1 to prime - 1
        myChoosenNumber = rand.nextLong();
        if(myChoosenNumber<0)   myChoosenNumber*=-1;
        myChoosenNumber=myChoosenNumber%(prime-1)+1;
        
        //generate the public key to be shared with the other user
        publicKey = power(primitiveRoot,myChoosenNumber,prime);
        
        //start a thread to listen to messages received from the another user
        new Thread(new Listener(portOfSender)).start();
        
        //Send public key
        sendPublicKey(portOfReceiver);
    }
    
    //Modular exponentiation
    public long power(long n,long p,long mod)
    {
        long x = 1;
        
        while(p!=0){
            if(p%2==1)  x = (x*n)%mod;
            n = (n*n)%mod;
            p/=2;
        }
        
        return x;
    }
    
    //Create the shared private key
    public void createSharedKey(long B)
    {
        sharedKey = power(B,myChoosenNumber,prime);
        System.out.println("SharedKey is : "+sharedKey);
        //initialize an instance of des using the created
        //shared key to enccrypt and decrypt messaes
        des = new DataEncryptionStandard(sharedKey);
    }
    
    //Send the generated public key
    public void sendPublicKey(int port)
    {
        String message = PUBLICKEY+" "+DELIMITER+publicKey;
        
        send(message,port);
    }
    
    //Encrypt message using the shared key
    public String encrypt(String message)
    {
        return des.encrypt(message);
    }
    
    //Decrypt message using the shared key
    public String decrypt(String message)
    {
        return des.decrypt(message);
    }
    
    //Send message to receiver
    public void send(String message,int port)
    {
        String receiverIP = "localhost";
        boolean exceptionCaught = true;
        do{
            try{
                
                Socket socket = new Socket(receiverIP,port);
                
                PrintWriter pw = new PrintWriter(socket.getOutputStream(),true);
                
                pw.println(message);
                
                exceptionCaught = false;
            }catch(IOException e){
                //System.out.println(e.getMessage());
            }
            
        }while(exceptionCaught);
    }
    
    //Receive message from receiver and decrypt the message
    //using shared key
    public void receive(String st)
    {
        System.out.println(st);
        String[] messages = st.split(":");
        
        if(messages[0].trim().equals(PUBLICKEY)){
            
            createSharedKey(Long.parseLong(messages[1]));
            
        }
        else {
            StringBuilder message = new StringBuilder(messages[1]);
            
            for(int i=2;i<messages.length;i++)
                message.append(DELIMITER+messages[i]);
            
            System.out.println(MESSAGE+" "+DELIMITER+decrypt(message.toString()));
        }
    }
    
    //Listener class to receive any incoming message
    private class Listener implements Runnable
    {
        int port;
        
        Listener(int port)
        {
            this.port = port;
        }
        
        public void run()
        {
            try{
                ServerSocket serverSocket = new ServerSocket(port);
                
                while(true){
                    
                    Socket socket = serverSocket.accept();
                    
                    BufferedReader br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    
                    receive(br.readLine());
                    
                }
            }catch(IOException e){
                System.out.println(e.getMessage());
            }
        }
    }
    
    //encrypt message before sending using shared key
    public void sendMessage(String message,int portOfReceiver)
    {
        message = MESSAGE+" "+DELIMITER+encrypt(message);
        
        send(message,portOfReceiver);
    }
    
    public static void main(String[] args) throws IOException
    {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        long prime,primitiveRoot;
        int portOfReceiver,portOfSender;
        
        portOfSender = Integer.parseInt(args[0]);
        portOfReceiver = Integer.parseInt(args[1]);
        prime = Long.parseLong(args[2]);
        primitiveRoot = Long.parseLong(args[3]);
        
        DiffieHellman dh = new DiffieHellman(prime,primitiveRoot,portOfSender,portOfReceiver);
        
        while(true){
            dh.sendMessage(br.readLine(),portOfReceiver);
        }
    }
}
