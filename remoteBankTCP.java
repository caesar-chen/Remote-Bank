//  socket related import
import java.net.Socket;
import java.net.SocketException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
// generateMD5 related import
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class remoteBankTCP {

  public static void main(String[] args) throws IOException,
    UnsupportedEncodingException, NoSuchAlgorithmException {

    //  variables will be used
    boolean debug = false;
    String username, password, instruct, amount;
    String rawHash, authenRequest, challString, response;


    //  handle illegal arguments
    if (args.length != 5) {
        if (args.length != 6 || !args[5].equals("-d")) {
            throw new IllegalArgumentException("Parameter(s): <Server:Port> " + 
        "<Username> <Password> <Action> <Amount> [<Debug>]");
        } else {
            debug = true;
        }
    }

    // get all info from command line, handle invalid input
    String server = args[0].split(":")[0];
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
    instruct = args[3];
    if (!instruct.equalsIgnoreCase("deposit") && !instruct.equalsIgnoreCase("withdraw")) {
          System.out.println("Invalid Operation!");
          return;
    }
    amount = args[4].trim();
    try {
        Double.valueOf(amount);
    }
    catch(NumberFormatException e) {
        System.out.println("Invalid Amount of Money");
        return;
    }

    // Create socket that is connected to server on specified port
    Socket socket;
    try {
        socket = new Socket(server, servPort);
    } catch(UnknownHostException e) {
        System.out.println("Invalid server address");
        return;
    }
    if (debug) System.out.println("Connected to server " + server + " at port #" + servPort);

    InputStream in = socket.getInputStream();
    OutputStream out = socket.getOutputStream();
    DataOutputStream sendTo = new DataOutputStream(out);
    BufferedReader recevFrom = new BufferedReader(new InputStreamReader(in));

    //authentication request
    if (debug) System.out.println("Sending Authentication Request to Server");
    authenRequest = "Request for Authentication";
    sendTo.writeBytes(authenRequest + "\n");

    //get challenge string from server
    if (debug) System.out.println("Getting challenge...");
    challString = recevFrom.readLine();
    if (debug) System.out.println("Challenge is " + challString);

    // send username to server
    if (debug) System.out.println("Send Username to Server");
    sendTo.writeBytes(username + "\n");

    //concatenating username + password + challenge
    if (debug) System.out.println("Compute Hash Using MD5");
    rawHash = username + password + challString;
    byte[] hash = generateMD5(rawHash);
    StringBuffer sb = new StringBuffer();
    for (byte b : hash) {
        sb.append(String.format("%02x", b & 0xff));
    }
    if (debug) System.out.println("Hash is: " + sb.toString());

    // send hash to server
    sendTo.writeBytes(sb.toString() + "\n");
    if (debug) System.out.println("Sending Hash to Server");

    //  server's response about the request
    response = recevFrom.readLine();
    System.out.println(response);
    if (!response.equals("Verified")) {
        System.out.println("Not Verified");
        socket.close();  // Close the socket and its streams
        return;
    }

    //  send action(deposit or withdraw)
    if(debug) System.out.println("Sending Action to Server...");
    sendTo.writeBytes(instruct + "\n");

    //  send the amount of money
    if(debug) System.out.println("Sending Amount to Server...");
    sendTo.writeBytes(amount + "\n");

    //  get how much money remains in the bank from server's response
    if(debug) System.out.println("Get Remain Money From Server");
    System.out.println(recevFrom.readLine());
    if(debug) System.out.println("Finished, Close Server");

    socket.close();  // Close the socket and its streams
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
