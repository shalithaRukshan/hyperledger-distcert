package com.ucd.mno;

import com.ucd.util.Constants;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.hyperledger.fabric.gateway.Contract;
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
    public static String nrfhost = "10.0.2.15";
    public static String nfprod = "10.0.2.15";
    public static int nrfport = 9500;
    public static int nfProdPort = 9501;

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
            Contract contract = network.getContract("basic");

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

            Socket nfSocket = new Socket(nfprod, nfProdPort);
            is = nfSocket.getInputStream();
            os = nfSocket.getOutputStream();

            in = new BufferedReader(new InputStreamReader(is));
            out = new PrintWriter(os, true);

            out.println("NFCcert");
            String nfCert = in.readLine();
            result = contract.evaluateTransaction("ValidateCert", nfCert);

            out.println("serviceReq||" + authToken + "||slice10");

            String service = in.readLine();

            System.out.println("\n");
            result = contract.evaluateTransaction("GetAllMNOs");
            System.out.println("Evaluate Transaction: GetAllAssets, result: " + new String(result));


        } catch (Exception e) {
            System.err.println(e);
        }

    }

}
