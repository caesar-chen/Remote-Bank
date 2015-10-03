//  socket related import
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap; // to store user info
import java.util.Random; // to generate challenge
// generateMD5 related import
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.UnsupportedEncodingException;

public class bankServerUDP {

  private static final int ECHOMAX = 255; // Maximum size of echo datagram
  // authenRequest request
  private static final String authenRequest = "Request for Authentication";

  public static void main(String[] args) throws IOException,
    UnsupportedEncodingException, NoSuchAlgorithmException {

    boolean debug = false;

    //User name and password
    HashMap<String, String> userList = new HashMap<String, String>();
    userList.put("Jack", "jack123");
    userList.put("Caesar", "caesar123");
    userList.put("Rose", "rose123");
    userList.put("DrEvil", "minime123");

    //Bank infomation
    HashMap<String, Double> bankInfo = new HashMap<String, Double>();
    bankInfo.put("Jack", 1100.0);
    bankInfo.put("Caesar", 500.0);
    bankInfo.put("Rose", 20.2);
    bankInfo.put("DrEvil", 99.9);

    // Connection infomation for each client is stored in Hashmap
    // Since we support multiple clients
    HashMap<String, Integer> clientsState = new HashMap<String, Integer>();
    HashMap<String, String> clientsChallenge = new HashMap<String, String>();
    HashMap<String, String> clientsUsername = new HashMap<String, String>();
    HashMap<String, String> clientsCommand = new HashMap<String, String>();
    HashMap<String, Integer> clientsAmount = new HashMap<String, Integer>();

    // Test for correct # of args
    if (args.length != 1) {
      if (args.length != 2 || !args[1].equals("-d")) {
        throw new IllegalArgumentException("Parameter(s): <Port>");
      } else {
        debug = true;
      }
    }

    // get all info from command line, and handle invalid inputs
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

    // init socket and packet
    DatagramSocket socket = new DatagramSocket(servPort);
    DatagramPacket packet = new DatagramPacket(new byte[ECHOMAX], ECHOMAX);

    // need to specify the port communicate with client
    int port;
    // which client is talking to right now
    String clientID;

    while (true) { // Run forever, receiving and echoing datagrams
      socket.receive(packet); // Receive packet from client
      if (debug) System.out.println("Handling client at " + packet.getAddress().getHostAddress() + " on port " + packet.getPort());
      InetAddress serverAddress = InetAddress.getByName(packet.getAddress().getHostAddress());
      
      port = packet.getPort();

      //uniquelly identify a client
      clientID = packet.getAddress().getHostAddress() + port;

      // request from client
      String data = new String(packet.getData());

      // send to client
      DatagramPacket toClient;

      if (debug) System.out.println("Wait client at " + serverAddress);
      if (debug) System.out.println(data);
      // if it's authenRequest
      if ((data.trim()).equals(authenRequest) || !clientsState.containsKey(clientID)) {
        // set the client state to 0
        clientsState.put(clientID, 0);
        if (debug) System.out.println("Generating Challenge");
        // generate challenge
        String temp = challenge();
        if (debug) System.out.println("challeng is " + temp);
        if (debug) System.out.println("Received request, now sending challenge string");
        // store challenge for this client
        clientsChallenge.put(clientID, temp);
        byte[] bytesToSend = temp.getBytes();
        // send challenge to client
        toClient = new DatagramPacket(bytesToSend, bytesToSend.length, serverAddress, port);
        socket.send(toClient); // Send the same packet back to client
        packet.setData(new byte[ECHOMAX]);
        packet.setLength(ECHOMAX); // Reset length to avoid shrinking buffer
      } else {
        // after authenRequest, we are now in state machine
        int state = clientsState.get(clientID);
        // get username, send ack
        if (state == 0) {
          if (debug) System.out.println("Get Username form client");
          clientsUsername.put(clientID, data.trim());
          clientsState.put(clientID, 1);
          String userConfirm = "Username ACK";
          if (debug) System.out.println("Sending Username ACK");
          toClient = new DatagramPacket(userConfirm.getBytes(), userConfirm.getBytes().length, serverAddress, port);
          socket.send(toClient);
        }
        else if (state == 1) {
          // check username first, then get hash, send ack
          if (debug) System.out.println("Get Hash form client "+ new String(data.trim()));
          String username = clientsUsername.get(clientID);
          if (debug) System.out.println("Validate Username");
          if (!userList.containsKey(username)) {
            String failure = "Wrong username!";
            toClient = new DatagramPacket(failure.getBytes(), failure.getBytes().length, serverAddress, port);
            socket.send(toClient);
            // clear cache if the username doesn't exist in database
            clientsState.remove(clientID);
            clientsUsername.remove(clientID);
            clientsChallenge.remove(clientID);
            System.out.println("Wrong username.");
            continue;
          }
          // generate MD5 on server side
          String password = userList.get(username);
          String chall = clientsChallenge.get(clientID);
          String rawHash = username + password + chall;
          byte[] digest = generateMD5(rawHash);
          StringBuffer sb = new StringBuffer();
          for (byte b : digest) {
          sb.append(String.format("%02x", b & 0xff));
          }
          if (debug) System.out.println("HashFromServer: " + sb.toString());
          if (debug) System.out.println("Validate Hash");
          // compare MD5 with client
          if (!sb.toString().equals(data.trim())) {
            String failure = "Wrong Password!";
            toClient = new DatagramPacket(failure.getBytes(), failure.getBytes().length, serverAddress, port);
            socket.send(toClient);
            // clear cache
            clientsState.remove(clientID);
            clientsUsername.remove(clientID);
            clientsChallenge.remove(clientID);
            System.out.println("Wrong password.");
            continue;
          }
          if(debug) System.out.println("Authentication Successful.");
          String success = "Verified";
          if(debug) System.out.println("Sending Confirm Back To Client");
          toClient = new DatagramPacket(success.getBytes(), success.getBytes().length, serverAddress, port);
          socket.send(toClient);
          clientsState.put(clientID, 2);
        } else if(state == 2) {
          // Getting instruction from client
          if (debug) System.out.println("Get command");
          if (debug) System.out.println("Command: " + data);
          data = data.trim();
          String askamount = "ActionACK";
          if (debug) System.out.println("Send aciton ACK");
          toClient = new DatagramPacket(askamount.getBytes(), askamount.getBytes().length, serverAddress, port);
          socket.send(toClient); 
          clientsState.put(clientID, 3);
          clientsCommand.put(clientID, data);
        } else if (state == 3) {
          // Getting amount from client
          if (debug) System.out.println("Get Amount");
          String usernameOnfile = clientsUsername.get(clientID);
          String action = clientsCommand.get(clientID);
          String reply;
          double currentValue = bankInfo.get(usernameOnfile);
          double amountInDouble = Double.valueOf(data);
          if (debug) System.out.println("Ammount is " + amountInDouble);
          // excute on account
          if (action.equalsIgnoreCase("deposit")) {
            if (amountInDouble < 0) {
              System.out.println("You can't deposit negative amount");
              if (debug) System.out.println("Transaction Fail");
              reply = "You can't deposit negative amount";
            } else {
              double newBalance = currentValue + amountInDouble;
              bankInfo.put(usernameOnfile, newBalance);
              reply = "Your new account balance is " + newBalance;
              if (debug) System.out.println("Transaction Success");
            }
          } else {
            if (amountInDouble < 0) {
              System.out.println("You can't withdraw negative");
              reply = "You can't withdraw negative amount";
              if (debug) System.out.println("Transaction Fail");
            } else if (currentValue >= amountInDouble) {
              bankInfo.put(usernameOnfile, currentValue - amountInDouble); 
              reply = "New account balance is " + (currentValue - amountInDouble);
            } else {
              reply = "Not enough money";
            }
          }
          // send feedback about account infomation to client
          toClient = new DatagramPacket(reply.getBytes(), reply.getBytes().length, serverAddress, port);
          socket.send(toClient);
          if (debug) System.out.println("Transaction Finished");
          System.out.println(reply);
          // clean up the cache for client after finished
          clientsState.remove(clientID);
          clientsUsername.remove(clientID);
          clientsChallenge.remove(clientID);
          clientsCommand.remove(clientID);
        }
        //  After finished, reset the packet
        if (debug) System.out.println("Reset packet");
        packet.setData(new byte[ECHOMAX]);
        packet.setLength(ECHOMAX); 
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
