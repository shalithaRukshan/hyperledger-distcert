package com.ucd.mno;

import com.ucd.util.Constants;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.ContractException;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;
import org.hyperledger.fabric.gateway.Wallets;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.sql.Timestamp;
import java.time.Instant;


public class Application {

    private static final Logger logger = LogManager.getLogger(Application.class);
    public static KeyPair keyPair;
    public static String host = "10.0.2.15";
    public static int port = 9500;
    public static Contract contract = null;

    static {
        System.setProperty("org.hyperledger.fabric.sdk.service_discovery.as_localhost", "true");
    }

    // helper function for getting connected to the gateway
    public static Gateway connect() throws Exception {
        // Load a file system based wallet for managing identities.
        Path walletPath = Paths.get("wallet");
        Wallet wallet = Wallets.newFileSystemWallet(walletPath);
        // load a CCP
        Path networkConfigPath = Paths.get("connection-acme.json");

        Gateway.Builder builder = Gateway.createBuilder();
        builder.identity(wallet, Constants.MNO_NAME).networkConfig(networkConfigPath).discovery(true);
        return builder.connect();
    }

    public static void main(String[] args) throws Exception {
        // enrolls the admin and registers the user
        System.out.println("starting app ");

        try {
            EnrollAdmin.enrollAdmin(null);
            RegisterUser.enrollUser(null);
        } catch (Exception e) {
            System.err.println(e);
        }

        // connect to the network and invoke the smart contract
        try (Gateway gateway = connect()) {

            // get the network and contract
            Network network = gateway.getNetwork("mychannel");
            System.out.println(network.getChannel().getPeers());
            contract = network.getContract("basic");

            byte[] result;

            Socket NRFSocket = new Socket(nrfhost, nrfport);
            InputStream is = NRFSocket.getInputStream();
            OutputStream os = NRFSocket.getOutputStream();

            BufferedReader in =
                    new BufferedReader(new InputStreamReader(is));
            PrintWriter out = new PrintWriter(os, true);

            out.println("Certificate");

            String nrfCert = in.readLine();
            result = contract.evaluateTransaction("ValidateCert", nrfCert);


            out.println("nf||slice1");
            String authToken = in.readLine();

            in.close();
            out.close();
            NRFSocket.close();

            Socket nfSocket = new Socket(nrfhost, nrfport);
            is = nfSocket.getInputStream();
            os = nfSocket.getOutputStream();

            in =
                    new BufferedReader(new InputStreamReader(is));
            out = new PrintWriter(os, true);

            out.println("certificate");
            String nfCert = in.readLine();
            result = contract.evaluateTransaction("ValidateCert", nfCert);

            out.println("serviceReq||" + authToken);

            String service = in.readLine();

            System.out.println("\n");
            result = contract.evaluateTransaction("GetAllMNOs");
            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));


        } catch (Exception e) {
            System.err.println(e);
        }


    }

    public static void handlesocket() {

        try {
            ServerSocket serverSocket = new ServerSocket(port);
            Socket socket = null;
            while (true) {
                try {
                    socket = serverSocket.accept();
                } catch (IOException e) {
                    System.out.println("I/O error: " + e);
                }
                // new thread for a client
                new NRFThread(socket).start();
            }

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
    }

    public static class NRFThread extends Thread {
        protected Socket socket;

        public NRFThread(Socket clientSocket) {
            this.socket = clientSocket;
        }

        public void run() {
            try {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                byte[] result;
                String cert = in.readLine();
                result = contract.evaluateTransaction("ValidateCert", cert);

                out.println("Certificate");

                String authRequest = in.readLine();

                if(authRequest.equals("AuthRequest")) {
                    out.println("AuthToken");
                }
                else if(authRequest.equals("AuthValidate")){
                    result = contract.evaluateTransaction("ValidateSlice", cert);
                    out.println(result);
                }else{
                    //todo
                }

                in.close();
                out.close();
                socket.close();
                logger.info("Connections closed");
            } catch (IOException | ContractException e) {
                e.printStackTrace();
            }
        }
    }


    public static BigInteger calSign(String data) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {

        Signature sig = Signature.getInstance("ECDSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = sig.sign();
        return new BigInteger(signatureBytes);

    }

    private static KeyPair getPoint() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecParameterSpec, new SecureRandom());

        KeyPair pair = keyPairGenerator.generateKeyPair();

        return pair;

    }

    public static String calHMAC(String signId, String msg) {

        return String.valueOf(HmacUtils.hmacSha256(signId, msg));
    }

    private static long getTimestamp() {
        Timestamp ts = Timestamp.from(Instant.now());
        return ts.getTime();
    }

    public static String[] decryptMsgMNO(String request) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
        BigInteger reqBg = new BigInteger(request);
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decMsg = cipher.doFinal(reqBg.toByteArray());
        String decryptedReq = new String(new BigInteger(decMsg).toByteArray());
        logger.info("decrytped text " + decryptedReq);
        String[] requestParts = decryptedReq.split("\\|\\|");
        logger.info("Received message contains " + requestParts.length + " parts");

        if (requestParts.length == 4) {
            logger.info("Executing the dos resolving process");
            return requestParts;
        } else {
            logger.error("Unknown msg type");
        }
        return null;
    }
}
