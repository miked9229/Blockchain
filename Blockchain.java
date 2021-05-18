// handles the Date functionality for the block

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

// MessageDigest objects handle functionality of hash functions like SHA-1 or SHA-256

import java.security.MessageDigest;

// Utility library that helps in the creation of UUIDs

import java.util.UUID;

// Utility library o create random numbers

import java.util.Random;

// Utility functions for dealing with JSON data
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

// Utility used for reading and writing to files
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;

// Utility class that handles Input and Output exception
import java.io.IOException;

// Utility that deals with dates and time stamps
import java.util.Date;

import java.util.Collection;
import java.util.Collections;
import java.lang.Object;

// Library that handles network traffic
import java.net.*;

// Library that handles input and output
import java.io.*;

// scanners parse the primitive types and strings using regular expressions
import java.util.Scanner;

// utility library the handles Arrays
import java.util.Arrays;

import java.util.Iterator;

// import the libraries that handle pulbic and private keys
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.spec.*;
import java.security.*;

// library for dealing with base64 encoding
import java.util.Base64;

// library for dealing with LinkedList objects
import java.util.LinkedList;

// Library to deal with Iterators and any other items I may have missed
import java.util.concurrent.*;
import java.util.function.Consumer;

// Library to handle Comparator

import java.util.Comparator;


public class Blockchain {

    // static variable that keeps track of the process id of the process running

    public static int processID = 0;

    // static variable that is used to keep track of the receivedProcessID from other processes

    public static int recievedProcessID = 0;

    // This HashMap object is used to store a process id and its associated public key for decryption

    public static HashMap<Integer, String> publicKeyRecord = new HashMap<Integer, String>();

    PriorityBlockingQueue<BlockRecord> ourPriorityQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);

    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
        
    // This is an annonymous inner class used to specify how to compare two blocks
        {

        @Override
        public int compare(BlockRecord b1, BlockRecord b2)
          {
       String s1 = b1.getTimeStamp();
       String s2 = b2.getTimeStamp();
       if (s1 == s2) {return 0;}
       if (s1 == null) {return -1;}
       if (s2 == null) {return 1;}
       return s1.compareTo(s2);
      }
    };
    // static variable that keeps track of the file name associated with the process

    public static String fileName;

    // server name that is associated with the Blockchain process in this case 
    // it is the local host

    public static String serverName = "localhost";

    // total number of processes that are involved in the Blockchain program
    public static int numProcesses = 3;


    // Variables for the the public / private keys used by the system

    public static KeyPair keyPair =  null;

    // A linked list that is added to when unverified blocks are read into the system

    public static LinkedList<BlockRecord> myBlocks = new LinkedList<BlockRecord>();

    // A linked list that is added to when blocks are verified. 

    public static LinkedList<BlockRecord> verifiedBlocks = new LinkedList<BlockRecord>();
    
    // indices of the information in the unverified blocks and given human-readable
    // names. Thank you very much Professor Clark Elliott

    private static final int iFNAME = 0;
    private static final int iLNAME = 1;
    private static final int iDOB = 2;
    private static final int iSSNUM = 3;
    private static final int iDIAG = 4;
    private static final int iTREAT = 5;
    private static final int iRX = 6;

    // alpha-numeric string that is used to generate a random seed in the doWork() program

    public static String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // a place to store the blockchain

    public static String blockchainString = "";

    public static BlockRecord[] mybBlockRecords;
    

    public Blockchain(String argv[]) {}

     public static void main(String[] args) {

        Blockchain newBlockchainProgram = new Blockchain(args);
        newBlockchainProgram.run(args);
        
    }

    public void run(String argv[]) {

        System.out.println("Michael Doroff's Blockchain Program Running.....");

        Blockchain.processID = (argv.length < 1) ? 0: Integer.parseInt(argv[0]);

        // The Ports class sets the ports of the initial Blockchain program
        // based on the process id that is fed in via the command-line arguments
        new Ports().setPorts();

        // Starting a new ProcessIDReceivingServer to receive broadcasted process IDs
        // from other processes
        new Thread(new ProcessIDReceivingServer()).start();

        // Starting a new PublicKeyReceivingServer to receive broadcasted public keys
        // from other processes

        new Thread(new PublicKeyReceivingServer()).start(); 

        // Starts up the Unverified Block Receiving Server and gives it the Priority Queue object
        // where we store unverified blocks read in by the three different processes

        new Thread(new UnverifiedBlockReceivingServer(ourPriorityQueue)).start();

        // Starts a server listening for multicasts of blockchains 

        new Thread(new BlockchainReceivingServer()).start();

        // sleeps while we start up the unverified block server

        try{Thread.sleep(6000);}catch(Exception e){} 

        // method that is used to read in the data of the unverified blocks and broadcast it to
        // the other processes

        try {

          Blockchain.keyPair = generateKeyPair(999);

          sendKey();

        } catch (Exception excp) {

          excp.printStackTrace();;
        }


        readInDataAndBroadcast();

       
        new Thread(new ConsumerBlockReceivingServer(ourPriorityQueue)).start();

    }

    public void sendKey() {

      Socket sock;
      PrintStream toServer;

      try {


      // convert the key to its byte form

      byte[] bytePubkey = Blockchain.keyPair.getPublic().getEncoded();

      //  convert the public key to a string

      String stringKey = Base64.getEncoder().encodeToString(bytePubkey);

          for(int i=0; i< numProcesses; i++){// Send our public key to all servers.

            sock = new Socket(serverName, Ports.KeyServerPortBase + (i * 1000));
            toServer = new PrintStream(sock.getOutputStream());
            toServer.println(Blockchain.processID + " " + stringKey); 
            toServer.flush();
            sock.close();
          }

      } catch (Exception excp) {

          excp.printStackTrace();

      }

    } 

    public void readInDataAndBroadcast() {

        // finds the process id that is given via the command-line arguments

        switch (Blockchain.processID) {
    
          case 0: 
            Blockchain.fileName = "BlockInput0.txt";
            break;
    
          case 1: 
            Blockchain.fileName = "BlockInput1.txt";
            break;
    
          case 2:
          Blockchain.fileName = "BlockInput2.txt";
          break;
    
        }
    
        try {
    
          BufferedReader bufferedReader = new BufferedReader(new FileReader(Blockchain.fileName));
    
          String[] tokens = new String[10];
          String InputLineStr;
          String suuid;
          UUID idA;
          BlockRecord tempRec;
    
          StringWriter sw = new StringWriter();
    
          int n = 0;
    
          Socket UVBsock;
    
          while ((InputLineStr = bufferedReader.readLine()) != null) {
            BlockRecord BR = new BlockRecord();
            try{Thread.sleep(1001);}catch(InterruptedException e){}
            Date date = new Date();
            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
            String TimeStampString = T1 + "." + Blockchain.processID; 
            BR.setTimeStamp(TimeStampString);
            
            suuid = new String(UUID.randomUUID().toString());
            byte[] digitalSignature = signData(suuid.getBytes(), Blockchain.keyPair.getPrivate());

            BR.setBlockID(suuid);
            tokens = InputLineStr.split(" +");
            BR.setFname(tokens[iFNAME]);
              BR.setLname(tokens[iLNAME]);
              BR.setSSNum(tokens[iSSNUM]);
              BR.setDOB(tokens[iDOB]);
              BR.setDiag(tokens[iDIAG]);
              BR.setTreat(tokens[iTREAT]);
              BR.setRx(tokens[iRX]);
              BR.setProcessIdThatCreatedBlock(Blockchain.processID);
              BR.setSignature(digitalSignature);
    
            Blockchain.myBlocks.add(BR);
            n++;
         
          }
    
          Random r = new Random();
          Iterator<BlockRecord> iterator = myBlocks.iterator();
          ObjectOutputStream toServerOOS = null; 
          for(int i = 0; i < numProcesses; i++){
            iterator = myBlocks.iterator(); 

            while(iterator.hasNext()){

              UVBsock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + (i * 1000));
              toServerOOS = new ObjectOutputStream(UVBsock.getOutputStream());
              tempRec = iterator.next();
            
              Gson gson = new GsonBuilder().setPrettyPrinting().create();     
            
              toServerOOS.writeObject(gson.toJson(tempRec)); 
              toServerOOS.flush();
              UVBsock.close();
          } 
          }
          Thread.sleep((r.nextInt(9) * 100)); 
      }catch (Exception e) { 
    
          e.printStackTrace();
    
        }
      }
      public static void doWork(BlockRecord myBlock) {

        String concatRecord =
        myBlock.getBlockID() +
        myBlock.getVerificationProcessID() +
        myBlock.getPreviousHash() + 
        myBlock.getFname() +
        myBlock.getLname() +
        myBlock.getSSNum() +
        myBlock.getRx() +
        myBlock.getDOB() +
        myBlock.getRandomSeed();

        String blockString = concatRecord;
        String concatString = "";
        String stringOut = "";
        String randString = randomAlphaNumeric(8);

        int workNumber = 0;
        workNumber = Integer.parseInt("0000",16);

          try {


          for(int i=1; i<20; i++){ 

              if (Blockchain.mybBlockRecords != null) {

                for (BlockRecord block: Blockchain.mybBlockRecords) {
  
                  if (myBlock.BlockID.equals(block.BlockID)) {
  
                    // breaks out of the work algorithm  if a block is verified
                    break;
                  }
                  break;
                }
              } 
           
              // I can make the work problem more challenging by specifying that the work number needs to be smaller

              randString = randomAlphaNumeric(8);
              concatString = blockString + randString; 
              MessageDigest MD = MessageDigest.getInstance("SHA-256");
              byte[] bytesHash = MD.digest(concatString.getBytes("UTF-8"));

              stringOut = ByteArrayToString(bytesHash); 
              // System.out.println("Hash is: " + stringOut); 

              workNumber = Integer.parseInt(stringOut.substring(0,4),16); 
              
              // System.out.println("First 16 bits in Hex and Decimal: " + stringOut.substring(0,4) +" and " + workNumber);
              if (!(workNumber < 20000)){  
                // System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
              }

              Thread.sleep(1000);

              if (workNumber < 20000){
              
              // System.out.format("%d is less than 20,000 so we solved the puzzle\n\n", workNumber);

              //  previousHash = Blockchain.mybBlockRecords[Blockchain.mybBlockRecords.length - 1].WinningHash;

              if (Blockchain.mybBlockRecords == null) {

                myBlock.setWinningHash(stringOut);
                myBlock.setRandomSeed(randString);
                myBlock.setPreviousHash("");
                myBlock.setBlockNumber(0);
                break;

              } else {


                int prevBlockNumber = Blockchain.mybBlockRecords[Blockchain.mybBlockRecords.length - 1].getBlockNumber();
                String prevBlockHash = Blockchain.mybBlockRecords[Blockchain.mybBlockRecords.length - 1].getWinningHash();
                myBlock.setWinningHash(stringOut);
                myBlock.setRandomSeed(randString);
                myBlock.setBlockNumber(prevBlockNumber + 1);
                myBlock.setPreviousHash(prevBlockHash);

              }
            }
          }
        }
      
          catch(Exception ex)  {

          ex.printStackTrace();
          
        }

      }
      // helper function used to generate random alpha-number string

      public static String randomAlphaNumeric(int count) {

        StringBuilder builder = new StringBuilder();

        while (count-- != 0) {

            int character = (int)(Math.random()*Blockchain.ALPHA_NUMERIC_STRING.length());
            builder.append(Blockchain.ALPHA_NUMERIC_STRING.charAt(character));

        }

        return builder.toString();
      } 
      
      // helper function used to take a byte array and get back its string representation

      public static String ByteArrayToString(byte[] ba) {

        StringBuilder hex = new StringBuilder(ba.length * 2);

        for(int i=0; i < ba.length; i++){
            hex.append(String.format("%02X", ba[i]));
          }
          return hex.toString();
        }

        
        public static KeyPair generateKeyPair(long seed) throws Exception {

          KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
          SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
          rng.setSeed(seed);
          keyGenerator.initialize(1024, rng);
          
          return (keyGenerator.generateKeyPair());

        }

        public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
          Signature signer = Signature.getInstance("SHA1withRSA");
          signer.initSign(key);
          signer.update(data);
          return (signer.sign());
        }

        public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
          Signature signer = Signature.getInstance("SHA1withRSA");
          signer.initVerify(key);
          signer.update(data);
          
          return (signer.verify(sig));
        }
}

// The Ports class is used to set initial port values based on the process id
// of the command-line arguments of the program. We initiate a Public Key Server,
// Process ID Receiving Server, Unverified Block Server, and a Blockchain Receiving Server

class Ports { 
    public static int KeyServerPortBase = 4710;
    public static int UnverifiedBlockServerPortBase = 4820;
    public static int ProcessIDPortBase = 6053;
    public static int BlockchainServerPortBase = 4930;

  
    public static int KeyServerPort;
    public static int UnverifiedBlockServerPort;
    public static int ProcessIDPort;
    public static int BlockchainServerPort;

  
    public void setPorts(){
      KeyServerPort = KeyServerPortBase + (Blockchain.processID * 1000);
      UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + (Blockchain.processID * 1000);
      ProcessIDPort = ProcessIDPortBase + (Blockchain.processID * 1000);
      BlockchainServerPort = BlockchainServerPortBase + (Blockchain.processID * 1000);
     
    }
  }

  class ProcessIDReceivingServer implements Runnable {

    public void run(){
    
      // sets the total number of connections allowable for connection

      int q_len = 6;
  
      Socket keySock;
  
      System.out.println("Starting the Process ID input thread using " + Integer.toString(Ports.ProcessIDPort));
  
      try{
          ServerSocket servsock = new ServerSocket(Ports.ProcessIDPort, q_len);
          while (true) {
        keySock = servsock.accept();
        new ProcessIDReceivingWorker (keySock).start(); 
          }
      } catch (IOException ioe) {
        System.out.println(ioe);}
      }
  }

  class ProcessIDReceivingWorker extends Thread { 

    Socket sock;
    ProcessIDReceivingWorker (Socket s) {sock = s;}
    public void run(){
    try {
  
      BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
  
      String processID = "";
  
      while((processID = in.readLine()) != null){

        // after a connection is made to the ProcessID Receiving Server, we store the Received Port in a 
        // ReceivedProcessID variable.
  
        Blockchain.recievedProcessID = Integer.parseInt(processID);

      }
      sock.close(); 
      } catch (IOException x){
        x.printStackTrace();
      }
    }
  }

  class PublicKeyReceivingServer implements Runnable {

    public void run(){
  
      int q_len = 6;
  
      Socket keySock;
  
      System.out.println("Starting the Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
  
      try{
          ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
          while (true) {
        keySock = servsock.accept();
        new PublicKeyWorker (keySock).start(); 
          }
      } catch (IOException ioe) {
        System.out.println(ioe);}
      }
  }

class PublicKeyWorker extends Thread { 
    Socket keySock; 
    PublicKeyWorker (Socket s) {keySock = s;} 
    public void run(){
  try{
      BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
      String data = in.readLine();

      // The Public Key Receiving Server Worker will put any keys into the publicKeyRecord with 
      // an associated process id that is broadcasted from other processes

      String[] arrOfKey = data.split(" ");

      Blockchain.publicKeyRecord.put(Integer.parseInt(arrOfKey[0]), arrOfKey[1]);

      keySock.close(); 
  } catch (IOException x){
      x.printStackTrace();
      }
    }
  }

class UnverifiedBlockReceivingServer implements Runnable {

    PriorityBlockingQueue<BlockRecord> queue;

    UnverifiedBlockReceivingServer(PriorityBlockingQueue<BlockRecord> queue) {

      this.queue = queue;
    }

    public void run() {

      int q_len = 6;
      Socket blockSocket;

      System.out.println("Starting the Unverified Block thread using " + Integer.toString(Ports.UnverifiedBlockServerPort));        

      try {
            ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
            while (true) {
              blockSocket = servsock.accept();
    new UnverifiedBlockWorker (blockSocket, queue).start(); 
      }
  } catch (IOException ioe) {
    System.out.println(ioe);}
  }
}

class UnverifiedBlockWorker extends Thread {

    Socket sock;
    BlockingQueue queue = null;

    UnverifiedBlockWorker (Socket s, BlockingQueue queue) {
     
      sock = s;
      this.queue = queue;

    } 
    
    BlockRecord BR = new BlockRecord();

    public void run() {
  
      try {

        Gson gson = new GsonBuilder().setPrettyPrinting().create();    

        ObjectInputStream unverifiedIn = new ObjectInputStream(sock.getInputStream());

        String jsonString = (unverifiedIn.readObject().toString());

        BlockRecord bRecord = gson.fromJson(jsonString, BlockRecord.class);

        queue.add(bRecord);

      } catch (Exception excp) {

          excp.printStackTrace();
      }
  }
}

class ConsumerBlockReceivingServer implements Runnable {

    BlockingQueue queue = null;
  
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    String myBlockString = gson.toJson(Blockchain.myBlocks);
    Socket sock;
    PrintStream toServer;

    PriorityBlockingQueue<BlockRecord> myQueue;
  
    ConsumerBlockReceivingServer(PriorityBlockingQueue<BlockRecord> queue) {
  
          this.myQueue = queue;
        }
  
        public void run() {

          try  {

            while(true) {

              BlockRecord record = (BlockRecord) myQueue.take();
  
              String publicKey = Blockchain.publicKeyRecord.get(record.getProcessIdThatCreatedBlock());
  
              byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
  
              X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyBytes);
  
              try {
  
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
  
                PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);
  
                boolean verified = verifySig(record.BlockID.getBytes(), RestoredKey, record.getSignature());
  
                System.out.println("Has the signature been verified: " + verified + "\n");
  
              } catch (Exception excp) {
  
                excp.printStackTrace();
              }
  
              Blockchain.doWork(record);
  
              Blockchain.verifiedBlocks.add(record);
    
              try{
    
                  ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
    
                  for(int i=0; i< Blockchain.numProcesses; i++){
    
                    sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + (i * 1000));
                    toServerOOS = new ObjectOutputStream(sock.getOutputStream());
                    toServerOOS.writeObject(gson.toJson(Blockchain.verifiedBlocks)); // Send the current blockchain after verification
                    toServerOOS.flush();
                    sock.close();
                   
                  }
              }catch (Exception x) {
                x.printStackTrace();
              }
          }

          } catch (Exception excp) {

            excp.printStackTrace();

          }

          
        //   Iterator iterator = queue.iterator();

        //   while (iterator.hasNext()) {
  
        //     BlockRecord record = (BlockRecord) iterator;

        //     String publicKey = Blockchain.publicKeyRecord.get(record.getProcessIdThatCreatedBlock());

        //     byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);

        //     X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(publicKeyBytes);

        //     try {

        //       KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        //       PublicKey RestoredKey = keyFactory.generatePublic(pubSpec);

        //       boolean verified = verifySig(record.BlockID.getBytes(), RestoredKey, record.getSignature());

        //       System.out.println("Has the signature been verified: " + verified + "\n");

        //     } catch (Exception excp) {

        //       excp.printStackTrace();
        //     }

        //     Blockchain.doWork(record);

        //     Blockchain.verifiedBlocks.add(record);
  
        //     try{
  
        //         ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
  
        //         for(int i=0; i< Blockchain.numProcesses; i++){
  
        //           sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + (i * 1000));
        //           toServerOOS = new ObjectOutputStream(sock.getOutputStream());
        //           toServerOOS.writeObject(gson.toJson(Blockchain.verifiedBlocks)); // Send the current blockchain after verification
        //           toServerOOS.flush();
        //           sock.close();
                 
        //         }
        //     }catch (Exception x) {
        //       x.printStackTrace();
        //     }
        // }
      }

      public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);
        
        return (signer.verify(sig));
      }
  }

class BlockchainReceivingServer implements Runnable {

    public void run(){
      
      int q_len = 6; /* Number of requests for OpSys to queue */
      Socket sock;
      System.out.println("Starting the Blockchain input thread using " + Integer.toString(Ports.BlockchainServerPort));
     
      try {
  
        ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
  
        while (true) {
          
          sock = servsock.accept();
          new BlockchainReceivingWorker (sock).start(); 
        }
      } catch (IOException ioe) {
  
        System.out.println(ioe);
      }    
    }
  }
  
  class BlockchainReceivingWorker extends Thread { 

    Socket sock;
    Gson gson = new GsonBuilder().setPrettyPrinting().create();    

    BlockchainReceivingWorker (Socket s) {sock = s;} 
    public void run(){
      try {

        ObjectInputStream unverifiedIn = new ObjectInputStream(sock.getInputStream());
  
        BlockRecord[] blocks = gson.fromJson(unverifiedIn.readObject().toString(), BlockRecord[].class);

        Blockchain.mybBlockRecords = blocks;
     
        // process id 0 will be the one writing the blockchain to disk

        if (Blockchain.processID == 0) {
  
          FileWriter fr = new FileWriter("BlockchainLedger.json");
  
          gson.toJson(blocks, fr);

          fr.close();
  
        } 
  
      } catch (Exception excp) {
  
          excp.printStackTrace();
  
      }
    }
  }
// Implements Serializable so we can send object across the socket
class BlockRecord implements Serializable {

    // variables that are given to us in the BlockInput files

    String BlockID;
    int BlockNumber;
    String VerificationProcessID;
    String PreviousHash; // hash of the previous block that was verified in the Blockchain
    UUID uuid; 
    String Timestamp;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;
    String RandomSeed; 
    String WinningHash; // winning hash that comes from the work program
    int processIdThatCreatedBlock;
    byte[] signature;


    // getters and settors used set and receive information about blocks verified and unverified blocks
    
    public String getBlockID() {return BlockID;}
    public void setBlockID(String BID){this.BlockID = BID;}

    public int getBlockNumber() { return BlockNumber;}
    public void setBlockNumber(int blockNumber){this.BlockNumber = blockNumber;}
  
    public String getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
    
    public String getPreviousHash() {return this.PreviousHash;}
    public void setPreviousHash (String PH){this.PreviousHash = PH;}
    
    public UUID getUUID() {return uuid;} 
    public void setUUID (UUID ud){this.uuid = ud;}

    public String getTimeStamp() { return Timestamp;}
    public void setTimeStamp(String timestamp) {this.Timestamp = timestamp; }
  
    public String getLname() {return Lname;}
    public void setLname (String LN){this.Lname = LN;}
    
    public String getFname() {return Fname;}
    public void setFname (String FN){this.Fname = FN;}
    
    public String getSSNum() {return SSNum;}
    public void setSSNum (String SS){this.SSNum = SS;}
    
    public String getDOB() {return DOB;}
    public void setDOB (String RS){this.DOB = RS;}
  
    public String getDiag() {return Diag;}
    public void setDiag (String D){this.Diag = D;}
  
    public String getTreat() {return Treat;}
    public void setTreat (String Tr){this.Treat = Tr;}
  
    public String getRx() {return Rx;}
    public void setRx (String Rx){this.Rx = Rx;}
  
    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed (String RS){this.RandomSeed = RS;}
    
    public String getWinningHash() {return WinningHash;}
    public void setWinningHash (String WH){this.WinningHash = WH;}

    public int getProcessIdThatCreatedBlock() {return processIdThatCreatedBlock;}
    public void setProcessIdThatCreatedBlock(int processId) {this.processIdThatCreatedBlock = processId;}

    public byte[] getSignature() {return signature;}
    public void setSignature(byte[] signature) {this.signature = signature;}
    
  }
  

