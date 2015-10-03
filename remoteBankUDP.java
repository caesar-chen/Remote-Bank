//  socket related import
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.io.IOException;
import java.io.InterruptedIOException;
// generateMD5 related import
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class remoteBankUDP {

  private static final int TIMEOUT = 3000;   // Resend timeout (milliseconds)
  private static final int MAXTRIES = 5;     // Maximum retransmissions

  public static void main(String[] args) throws IOException,
    UnsupportedEncodingException, NoSuchAlgorithmException {

    //  variables will be used
    boolean debug = false;
    String username, password, instruct, amount;
    String rawHash, authenRequest, challString, response;

    //  handle invalid arguments
    if (args.length != 5) {
        if (args.length != 6 || !args[5].equals("-d")) {
            throw new IllegalArgumentException("Parameter(s): <Server:Port> " + 
        "<Username> <Password> <Action> <Amount> [<Debug>]");
        } else {
            debug = true;
        }
    }

    // get all info from command line, and handle invalid inputs
    String server = args[0].split(":")[0];
    //  handle invalid port#
    int servPort;
    try {
        servPort = Integer.parseInt(args[0].split(":")[1]);
    }
    catch(NumberFormatException e) {
        System.out.println("Invalid Port #");
        return;
    }
    if(servPort < 1024 || servPort > 9999){
        System.out.println("Invalid port number. Only 1024-9999.");
        return;
    }
    username = args[1];
    password = args[2];
    // handle invalid action
    instruct = args[3];
    if (!instruct.equalsIgnoreCase("deposit") && !instruct.equalsIgnoreCase("withdraw")) {
          System.out.println("Invalid Operation!");
          return;
    }
    // handle invalid account
    amount = args[4].trim();
    try {
        Double.valueOf(amount);
    }
    catch(NumberFormatException e) {
        System.out.println("Invalid Amount!");
        return;
    }

    InetAddress serverAddress = InetAddress.getByName(server);  // Server address


    //  set max blocking time
    DatagramSocket socket = new DatagramSocket();
    if (debug) System.out.println("UDP Socket timeout is " + TIMEOUT/1000 + "s");
    socket.setSoTimeout(TIMEOUT);  // Maximum receive blocking time (milliseconds)

    //authentication request
    if (debug) System.out.println("Sending Authentication Request to Server");
    authenRequest = "Request for Authentication";
    byte[] ar = authenRequest.getBytes();
    DatagramPacket sendPacket = new DatagramPacket(ar,  // Sending packet
        ar.length, serverAddress, servPort);

    // receive packet
    DatagramPacket receivePacket = new DatagramPacket(new byte[64], 64);

    int tries = 0;      // Packets may be lost, so we have to keep trying
    boolean receivedResponse = false; //  response from server
    do {
      if (debug) System.out.println("Sending Authentication Request to Server");
      socket.send(sendPacket);          // Send the echo string
      try {
        socket.receive(receivePacket);  // Attempt echo reply reception
        if (!receivePacket.getAddress().equals(serverAddress)) {// Check source
          throw new IOException("Received packet from an unknown source");
	    }
        receivedResponse = true;
        tries = 0;
      } catch (InterruptedIOException e) {  // We did not get anything
        tries += 1;
        if (debug) System.out.println("Timed out, " + (MAXTRIES - tries) + " more tries...");
      }
    } while ((!receivedResponse) && (tries < MAXTRIES));
    // message can't be sent, something woring with network
    if (!receivedResponse) {
      System.out.println("No response -- giving up.");
      socket.close();
      return;
    }
    //  reset the flag
    receivedResponse = false;

    //get challenge string
    if (debug) System.out.println("Getting challenge...");
    challString = new String(receivePacket.getData());
    if (debug) System.out.println("Challenge is " + challString);

    //concatenating username + password + challenge
    if (debug) System.out.println("Compute Hash Using MD5");
    rawHash = username + password + challString;

    // calculate hash
    byte[] hash = generateMD5(rawHash);
    StringBuffer sb = new StringBuffer();
    for (byte b : hash) {
        sb.append(String.format("%02x", b & 0xff));
    }
    if (debug) System.out.println("Hash is: " + sb.toString());
    // reset receivePacket
    receivePacket.setData(new byte[128]);
    //  reset sendPacket
    sendPacket.setData(username.getBytes());
    sendPacket.setLength(username.getBytes().length);

    // send username
    do {
      if (debug) System.out.println("Sending username to Server");
      socket.send(sendPacket);          // Send the echo string
      try {
        socket.receive(receivePacket);  // Attempt echo reply reception
        if (!receivePacket.getAddress().equals(serverAddress)) {// Check source
          throw new IOException("Received packet from an unknown source");
        }
        receivedResponse = true;
        tries = 0;
      } catch (InterruptedIOException e) {  // We did not get anything
        tries += 1;
        if (debug) System.out.println("Timed out, " + (MAXTRIES - tries) + " more tries...");
      }
    } while ((!receivedResponse) && (tries < MAXTRIES));
    // message can't be sent, something woring with network
    if (!receivedResponse) {
      System.out.println("No response -- giving up.");
      socket.close();
      return;
    }
    //  reset flag
    receivedResponse = false;

    // ACK of username from server
    if (debug) System.out.println(new String(receivePacket.getData()));

    // send hash value to server
    byte[] hashValue = sb.toString().getBytes();
    receivePacket.setData(new byte[128]);
    sendPacket.setData(hashValue);
    sendPacket.setLength(hashValue.length);
    do {
      if (debug) System.out.println("Sending Hash to Server");
      socket.send(sendPacket);          // Send the echo string
      try {
        socket.receive(receivePacket);  // Attempt echo reply reception
        if (!receivePacket.getAddress().equals(serverAddress)) {// Check source
          throw new IOException("Received packet from an unknown source");
        }
        receivedResponse = true;
        tries = 0;
      } catch (InterruptedIOException e) {  // We did not get anything
        tries += 1;
        if (debug) System.out.println("Timed out, " + (MAXTRIES - tries) + " more tries...");
      }
    } while ((!receivedResponse) && (tries < MAXTRIES));
    //  something worong with network
    if (!receivedResponse) {
      System.out.println("No response -- giving up.");
      socket.close();
      return;
    }
    // reset flag
    receivedResponse = false;

    // ACK of respond from server
    response = new String(receivePacket.getData()).trim();
    System.out.println(response);

    //  check if password is correct or not
    if (!response.equals("Verified")) {
        System.out.println("Not Verified");
        socket.close();  // Close the socket and its streams
        return;
    }

    // send action to server
    sendPacket.setData(instruct.getBytes());
    sendPacket.setLength(instruct.getBytes().length);
    receivePacket.setData(new byte[128]);
    do {
      if(debug) System.out.println("Sending Action to Server...");
      socket.send(sendPacket);          // Send the echo string
      try {
        socket.receive(receivePacket);  // Attempt echo reply reception
        if (!receivePacket.getAddress().equals(serverAddress)) {// Check source
          throw new IOException("Received packet from an unknown source");
        }
        receivedResponse = true;
        tries = 0;
      } catch (InterruptedIOException e) {  // We did not get anything
        tries += 1;
        if (debug) System.out.println("Timed out, " + (MAXTRIES - tries) + " more tries...");
      }
    } while ((!receivedResponse) && (tries < MAXTRIES));
    //  something wrong with network
    if (!receivedResponse) {
      System.out.println("No response -- giving up.");
      socket.close();
      return;
    }
    // reset flag
    receivedResponse = false;

    // ACK of Action from server
    response = new String(receivePacket.getData());
    System.out.println(response);
    if (response.indexOf("Invalid Action") != -1) {
        System.out.println("Not valid Action");
        socket.close();  // Close the socket and its streams
        return;
    }

    // send amount to server
    sendPacket.setData(amount.getBytes());
    sendPacket.setLength(amount.getBytes().length);
    receivePacket.setData(new byte[128]);
    do {
      if(debug) System.out.println("Sending Amount to Server...");
      socket.send(sendPacket);          // Send the echo string
      try {
        socket.receive(receivePacket);  // Attempt echo reply reception
        if (!receivePacket.getAddress().equals(serverAddress)) {// Check source
          throw new IOException("Received packet from an unknown source");
        }
        receivedResponse = true;
        tries = 0;
      } catch (InterruptedIOException e) {  // We did not get anything
        tries += 1;
        if (debug) System.out.println("Timed out, " + (MAXTRIES - tries) + " more tries...");
      }
    } while ((!receivedResponse) && (tries < MAXTRIES));
    // something wrong with network
    if (!receivedResponse) {
      System.out.println("No response -- giving up.");
      socket.close();
      return;
    }
    
    // Ack of entire transaction from server
    System.out.println(new String(receivePacket.getData()));

    System.out.println("Thank you for banking with us.");
    socket.close();
  }

  //helper method for generateMD5
  private static byte[] generateMD5(String info) throws
    UnsupportedEncodingException, NoSuchAlgorithmException {
    byte[] inputData = info.getBytes("UTF-8");
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(inputData);
    byte[] digest= md.digest();
    return digest;
  }
}
