package ftp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 * Runs a server socket which waits for requests from FTPClient to come in over
 * the network.
 *
 * @author Arun
 *
 */
public class FileServer {
	static String dirLocation = "certificateandkeys/";
	/* For Linux - Uncomment the below line and comment the above line */
	// static String dirLocation = "../certificateandkeys/";

	static String fileLocation = "otherfiles/";
	/* For Linux - Uncomment the below line and comment the above line */
	// static String fileLocation = "../otherfiles/";
	static DigestSHA3 md = new SHA3.Digest512();

	/**
	 * Main method.
	 *
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		int portNumber = 1236;
		try (ServerSocket serverSocket = new ServerSocket(portNumber);) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate certficate = (X509Certificate) cf
					.generateCertificate(new FileInputStream(dirLocation + "server-certificate.crt"));
			byte[] sessionKey, iv, encodedCertificate = certficate.getEncoded();
			PrivateKey serverPrivateKey = getPrivateKey();
			Cipher cipher = Cipher.getInstance("RSA");
			while (true) {
				Socket client = serverSocket.accept();
				try {
					ObjectInputStream is = new ObjectInputStream(client.getInputStream());
					ObjectOutputStream os = new ObjectOutputStream(client.getOutputStream());
					os.writeObject(encodedCertificate);
					SessionKeyMessage statusOfCert = (SessionKeyMessage) is.readObject();
					if (statusOfCert.message.equals("failure"))
						continue;
					cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
					sessionKey = cipher.doFinal(statusOfCert.encryptedSessionKey);
					iv = cipher.doFinal(statusOfCert.encryptedIV);
					Message msg = (Message) is.readObject();
					if (msg instanceof DownloadMessage)
						send(os, new BigInteger(sessionKey), new BigInteger(iv), (DownloadMessage) msg);
					else
						receiveFile(is, new BigInteger(sessionKey), new BigInteger(iv), (UploadMessage) msg);
				} catch (SocketException e) {
					continue;
				}
			}
		} catch (ConnectException e) {
			System.out.println(
					"Exception caught when trying to listen on port " + portNumber + " or listening for a connection");
			System.out.println(e.getMessage());
		}
	}

	/**
	 * Reads the public key from the .key file.
	 *
	 * @return
	 * @throws Exception
	 */
	public static PublicKey getPublicKey() throws Exception {
		PEMParser pemParser = new PEMParser(new FileReader(dirLocation + "/server-public.key"));
		SubjectPublicKeyInfo object = (SubjectPublicKeyInfo) pemParser.readObject();
		pemParser.close();
		return (new JcaPEMKeyConverter()).getPublicKey(object);
	}

	/**
	 * Reads the private key from the .key file.
	 *
	 * @return
	 * @throws Exception
	 */
	public static PrivateKey getPrivateKey() throws Exception {
		PEMParser pemParser = new PEMParser(new FileReader(dirLocation + "/server-private.key"));
		PEMKeyPair object = (PEMKeyPair) pemParser.readObject();
		pemParser.close();
		return (new JcaPEMKeyConverter()).getPrivateKey(object.getPrivateKeyInfo());
	}

	/**
	 * This method writes the file content to the FTPClient socket during
	 * Download operation.
	 *
	 * @param os
	 * @param sessionKey
	 * @param iv
	 * @param msg
	 * @throws IOException
	 */
	public static void send(ObjectOutputStream os, BigInteger sessionKey, BigInteger iv, DownloadMessage msg)
			throws IOException {
		try {
			FileInputStream fis = new FileInputStream(fileLocation + msg.message);
			BigInteger macSessionKey = sessionKey.add(BigInteger.ONE);
			int nread;
			byte[] fileContents = new byte[64], cn, bn = md.digest(sessionKey.add(iv).toByteArray());
			while ((nread = fis.read(fileContents)) != -1) {
				cn = new byte[nread];
				for (int i = 0; i < nread; i++)
					cn[i] = (byte) (((int) fileContents[i]) ^ ((int) bn[i]));
				msg = new DownloadMessage("", cn);
				System.arraycopy(md.digest(
						macSessionKey.add(new BigInteger(Arrays.copyOfRange(fileContents, 0, nread))).toByteArray()), 0,
						msg.mac, 0, 16);
				os.writeObject(msg);
				bn = md.digest(sessionKey.add(new BigInteger(cn)).toByteArray());
			}
			msg = new DownloadMessage("", null);
			msg.exit = true;
			os.writeObject(msg);
			os.flush();
			fis.close();
		} catch (FileNotFoundException e) {
			msg.exit = true;
			os.writeObject(msg);
			return;
		}
	}

	/**
	 * This method reads the file content from the FTPClient socket during
	 * Upload operation.
	 *
	 * @param is
	 * @param sessionKey
	 * @param iv
	 * @param msg
	 * @throws Exception
	 */
	public static void receiveFile(ObjectInputStream is, BigInteger sessionKey, BigInteger iv, UploadMessage msg)
			throws Exception {
		FileOutputStream fos = new FileOutputStream(fileLocation + msg.message);
		byte[] pn, receivedMac = new byte[16], bn = md.digest(sessionKey.add(iv).toByteArray());
		BigInteger macSessionKey = sessionKey.add(BigInteger.ONE);
		msg = (UploadMessage) is.readObject();
		try {
			for (; !msg.exit; msg = (UploadMessage) is.readObject()) {
				pn = new byte[msg.fileContents.length];
				for (int i = 0; i < pn.length; i++)
					pn[i] = (byte) (((int) msg.fileContents[i]) ^ ((int) bn[i]));
				System.arraycopy(md.digest(macSessionKey.add(new BigInteger(pn)).toByteArray()), 0, receivedMac, 0, 16);
				if (!Arrays.equals(msg.mac, receivedMac))
					break;
				fos.write(pn);
				bn = md.digest(sessionKey.add(new BigInteger(msg.fileContents)).toByteArray());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		fos.flush();
		fos.close();
	}
}
