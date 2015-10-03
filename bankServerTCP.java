import java.net.*;  // for Socket, ServerSocket, and InetAddress
import java.io.*;   // for IOException and Input/OutputStream
import java.util.HashMap; // to store user info
import java.util.Random; // to generate challenge
//  generateMD5 related import
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class bankServerTCP {

  // timeout for server
  private static final int TIMEOUT = 5000;
  //  authentication request from client
  private static final String authenRequest = "Request for Authentication";

  public static void main(String[] args) throws IOException,
    UnsupportedEncodingException, NoSuchAlgorithmException {

    // variables will be used
    boolean debug = false;
    String username;
    String password;
    String clientHash;

    //User name and password database
    HashMap<String, String> userList = new HashMap<String, String>();
    userList.put("Jack", "jack123");
    userList.put("Caesar", "caesar123");
    userList.put("Rose", "rose123");
    userList.put("DrEvil", "minime123");

    //Bank infomation database
    HashMap<String, Double> bankInfo = new HashMap<String, Double>();
    bankInfo.put("Jack", 1100.0);
    bankInfo.put("Caesar", 500.0);
    bankInfo.put("Rose", 20.2);
    bankInfo.put("DrEvil", 99.9);

    // Test for correct # of args
    if (args.length != 1) {
      if (args.length != 2 || !args[1].equals("-d")) {
        throw new IllegalArgumentException("Parameter(s): <Port>");
      } else {
        debug = true;
      }
    }

    // get all info from command line, handle invalid input
    int servPort;
    try {
        servPort = Integer.parseInt(args[0]);
    }
    catch(NumberFormatException e) {
        System.out.println("Invalid Port #");
        return;
    }
    if(servPort < 1024 || servPort > 9999){
        System.out.println("Invalid port number. Only 1024-9999.");
        return;
    }

    // Create a server socket to accept client connection requests
    ServerSocket servSock = new ServerSocket(servPort);

    while (true) {
      Socket clntSock = servSock.accept();     // Get client connection
      clntSock.setSoTimeout(TIMEOUT);     // set timeout

      // in order to handle socket timeout situation
      try {
        //  get info about client
        SocketAddress clientAddress = clntSock.getRemoteSocketAddress();
        if (debug) System.out.println("Handling client at " + clientAddress);
        InputStream in = clntSock.getInputStream();
        OutputStream out = clntSock.getOutputStream();
        BufferedReader inFromClient = new BufferedReader(new InputStreamReader(in));
        DataOutputStream outToClient = new DataOutputStream(out);

        //generate challenge value
        String temp = challenge();

        // wait for client's authentication request
        if (debug) System.out.println("Waiting client to send Authentication Request");
        String flag;
        flag = inFromClient.readLine();
        // get it
        if (flag.equals(authenRequest)) {
          if (debug) System.out.println("Received request, now sending challeng string");
          outToClient.writeBytes(temp + "\n");
          if (debug) System.out.println("challeng is " + temp);
        } else {
          // didn't get request, error
          if (debug) System.out.println("Error, not authentication request");
          outToClient.writeBytes("Please authenticate first.\n");
          clntSock.close();
          continue;
        }

        //get username
        username = inFromClient.readLine();
        if (debug) System.out.println("Get Username: " + username);
        
        //get MD5 hash from client
        clientHash = inFromClient.readLine();
        if (debug) System.out.println("Get Hash From Client: " + clientHash);

        // Validate username
        if (debug) System.out.println("Validate Username");
        if (!userList.containsKey(username)) {
          System.out.println("Authentication Failed");
          outToClient.writeBytes("Invalid Username!" + "\n");
          clntSock.close();  // Close the socket.  We are done with this client!
          continue;
        }

        // Validate Hash by comparasion
        StringBuffer sb = new StringBuffer();
        if (debug) System.out.println("Validate Hash");
        password = userList.get(username);  
        String rowHash = username + password + temp;
        byte[] digest = generateMD5(rowHash);
        // generate hash from server side
        for (byte b : digest) {
          sb.append(String.format("%02x", b & 0xff));
        }
        if (debug) System.out.println("Check if Succeed Validate or Failed");
        //  compare value with client
        if (!sb.toString().equals(clientHash)) {
          if (debug) System.out.println("Wrong Password!");
          outToClient.writeBytes("Wrong Password!" + "\n");
          clntSock.close();  // Close the socket.  We are done with this client!
          continue;
        }
        outToClient.writeBytes("Verified" + "\n");
        
        // Getting command from client
        if (debug) System.out.println("Get command");
        String command;
        command = inFromClient.readLine();
        if (debug) System.out.println("Command is " + command);

        //  Validate command, handle error
        if (!command.equalsIgnoreCase("deposit") && !command.equalsIgnoreCase("withdraw")) {
          System.out.println("Invalid Operation!");
          clntSock.close();
          continue;
        }

        // Getting amount from client
        String amount;
        amount = inFromClient.readLine();
        if (debug) System.out.println("Ammount is " + amount);

        //  operation about client's banking infomation
        double amountInDouble = Double.valueOf(amount);
        double currentValue = bankInfo.get(username);
        if (command.equalsIgnoreCase("deposit")) {
          if (amountInDouble < 0) {
            System.out.println("You can't deposit negative amount to your account");
            outToClient.writeBytes("Amount must be greater than zero\n");
            if (debug) System.out.println("Transaction Fail");
          } else {
            double newBalance = currentValue + amountInDouble;
            bankInfo.put(username, newBalance);
            outToClient.writeBytes("Your new account balance is " + newBalance + "\n");
            if (debug) System.out.println("Transaction Success");
          }
        } else {
          // 1.withdraw negative number 2.don't have enough money on account
          if (amountInDouble < 0 || amountInDouble > currentValue) {
            System.out.println("You can't withdraw negative amount to your account or you account doesn't have enough money");
            outToClient.writeBytes("Fails, reasons maybe 1. Amount must be greater than zero or 2. not enough money in you account\n");
            if (debug) System.out.println("Transaction Fail");
          } else {
            double newBalance = currentValue - amountInDouble;
            bankInfo.put(username, newBalance);
            outToClient.writeBytes("Your new account balance is " + newBalance + "\n");
            if (debug) System.out.println("Transaction Success");
          }
        }
        if (debug) System.out.println("Transaction Finished!");
      }
      catch(SocketTimeoutException e) {     
          if (debug) System.out.println("Timeout!");
          clntSock.close();
          continue;
     }
    }
  }

  //helper method to generate challenge
  private static String challenge() {
      String AB = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
      Random rnd = new Random();
      StringBuilder sb = new StringBuilder(64);
      for( int i = 0; i < 64; i++) {
          sb.append(AB.charAt(rnd.nextInt(AB.length())));
      }
      String ret = sb.toString();
      return ret;
  }

  //helper method to generateMD5
  private static byte[] generateMD5(String info) throws
    UnsupportedEncodingException, NoSuchAlgorithmException {
    byte[] inputData = info.getBytes("UTF-8");
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(inputData);
    byte[] digest= md.digest();
    return digest;
  }
}
