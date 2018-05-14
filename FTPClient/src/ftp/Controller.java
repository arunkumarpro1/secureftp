package ftp;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.Cipher;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;

/**
 * This class contains all the controller methods for the UI components.
 *
 * @author Arun
 *
 */
public class Controller {

	static DigestSHA3 md = new SHA3.Digest512();
	SecureRandom random = new SecureRandom();

	@FXML
	private TextField filePath;

	@FXML
	private TextField downloadFileName;

	FileChooser fileChooser = new FileChooser();
	DirectoryChooser dirChooser = new DirectoryChooser();
	String serverHostName = "csgrads1.utdallas.edu";
	int serverPortNumber = 6000;
	Scanner s = new Scanner(System.in);
	byte[] encryptedSessionKey, encryptedIV;
	static BigInteger sessionKey, iv;
	Socket socket;
	ObjectOutputStream os;
	ObjectInputStream is;
	CertificateFactory cf;
	X509Certificate certficate;
	PublicKey serverPublicKey, caPublicKey;
	Cipher cipher;
	File file;

	/**
	 * This method extracts the server public key from the certificate once at
	 * startup.
	 *
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	@FXML
	private void initialize()
			throws IOException, ClassNotFoundException, InvalidKeyException, GeneralSecurityException {
		cf = CertificateFactory.getInstance("X.509");
		File f = new File("./");
		System.out.println(f.getAbsolutePath());
		certficate = (X509Certificate) cf
				.generateCertificate(new FileInputStream("../certificateandkeys/ashkan-certificate.crt"));
		caPublicKey = certficate.getPublicKey();
		cipher = Cipher.getInstance("RSA");

		dirChooser.setTitle("Select Folder To Save...");
	}

	/**
	 * Thi method opens the file browser.
	 *
	 * @throws InvalidKeyException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	@FXML
	public void chooseFile() throws InvalidKeyException, ClassNotFoundException, IOException, GeneralSecurityException {
		fileChooser.setTitle("Open File");
		file = fileChooser.showOpenDialog(filePath.getScene().getWindow());
		if (file != null)
			filePath.setText(file.getAbsolutePath());
	}

	/**
	 * Driver method to start the upload function.
	 *
	 * @throws InvalidKeyException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	@FXML
	public void uploadFile() throws InvalidKeyException, ClassNotFoundException, IOException, GeneralSecurityException {
		if (file != null) {
			if (openSocketAndExchangeSessionKey()) {
				send(os, file);
				filePath.clear();
				showSuccess("Upload Successful!");
			} else
				showError("Server could not be verified!");
		}
		file = null;
	}

	/**
	 * @throws InvalidKeyException
	 * @throws ClassNotFoundException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	@FXML
	public void downloadFile()
			throws InvalidKeyException, ClassNotFoundException, IOException, GeneralSecurityException {
		if (isValid(downloadFileName.getText())) {
			if (openSocketAndExchangeSessionKey()) {
				DownloadMessage m = new DownloadMessage(downloadFileName.getText(), null);
				os.writeObject(m);
				m = (DownloadMessage) is.readObject();
				if (!m.exit) {
					File dir = dirChooser.showDialog(downloadFileName.getScene().getWindow());
					if (dir != null) {
						boolean isSuccess = receive(is, dir.getAbsolutePath() + "\\" + downloadFileName.getText(), m);
						if (isSuccess)
							showSuccess("Download Successful!");
						else {
							deleteFile(dir.getAbsolutePath() + "\\" + downloadFileName.getText());
							showError("Error in Download!");
						}
						downloadFileName.clear();
					}
				} else
					showError("File Not Found!");
			} else
				showError("Server could not be verified!");
		}
	}

	private void deleteFile(String filename) {
		File f = new File(filename);
		f.delete();
	}

	/**
	 * Alerts error message.
	 *
	 * @param errorMsg
	 */
	private void showError(String errorMsg) {
		Alert alert = new Alert(AlertType.ERROR);
		alert.setTitle("Failure");
		alert.setContentText(errorMsg);
		alert.show();
	}

	/**
	 * Alerts success.
	 *
	 * @param successMsg
	 */
	private void showSuccess(String successMsg) {
		Alert alert = new Alert(AlertType.INFORMATION);
		alert.setTitle("Success");
		alert.setContentText(successMsg);
		alert.show();
	}

	/**
	 * @return
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	private boolean openSocketAndExchangeSessionKey()
			throws IOException, ClassNotFoundException, InvalidKeyException, GeneralSecurityException {
		socket = new Socket(serverHostName, serverPortNumber);
		os = new ObjectOutputStream(socket.getOutputStream());
		is = new ObjectInputStream(socket.getInputStream());
		byte[] cert = (byte[]) is.readObject();
		serverPublicKey = verifyServerCertificateAndGetPublicKey(cert, caPublicKey);
		SessionKeyMessage statusOfCert;
		if (serverPublicKey == null) {
			statusOfCert = new SessionKeyMessage("failure");
			os.writeObject(statusOfCert);
			return false;
		}
		sessionKey = new BigInteger(512, random);
		iv = new BigInteger(512, random);
		cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		encryptedSessionKey = cipher.doFinal(sessionKey.toByteArray());
		encryptedIV = cipher.doFinal(iv.toByteArray());
		statusOfCert = new SessionKeyMessage("success");
		statusOfCert.encryptedSessionKey = encryptedSessionKey;
		statusOfCert.encryptedIV = encryptedIV;
		os.writeObject(statusOfCert);
		return true;
	}

	/**
	 * Certificate verification.
	 *
	 * @param cert
	 * @param caPublicKey
	 * @return
	 */
	private static PublicKey verifyServerCertificateAndGetPublicKey(byte[] cert, PublicKey caPublicKey) {
		X509Certificate serverCertificate;
		try {
			serverCertificate = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new ByteArrayInputStream(cert));
			serverCertificate.checkValidity();
			serverCertificate.verify(caPublicKey);
		} catch (CertificateException | InvalidKeyException | NoSuchProviderException | SignatureException
				| NoSuchAlgorithmException e) {
			return null;
		}
		return serverCertificate.getPublicKey();
	}

	/**
	 * Writes the file content to the socket during Upload operation.
	 *
	 * @param os
	 * @param myFile
	 * @param sessionKey
	 * @param iv
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void send(ObjectOutputStream os, File myFile) throws NoSuchAlgorithmException, IOException {
		byte[] fileContents = new byte[64];
		UploadMessage m = new UploadMessage(myFile.getName(), fileContents);
		BigInteger macSessionKey = sessionKey.add(BigInteger.ONE);
		os.writeObject(m);
		FileInputStream fis = new FileInputStream(myFile);
		int nread;
		byte[] cn, bn = md.digest(sessionKey.add(iv).toByteArray());
		while ((nread = fis.read(fileContents)) != -1) {
			cn = new byte[nread];
			for (int i = 0; i < nread; i++)
				cn[i] = (byte) (((int) fileContents[i]) ^ ((int) bn[i]));
			m = new UploadMessage("", cn);
			System.arraycopy(md.digest(
					macSessionKey.add(new BigInteger(Arrays.copyOfRange(fileContents, 0, nread))).toByteArray()), 0,
					m.mac, 0, 16);
			os.writeObject(m);
			bn = md.digest(sessionKey.add(new BigInteger(cn)).toByteArray());
		}
		m = new UploadMessage("", null);
		m.exit = true;
		os.writeObject(m);
		os.flush();
		fis.close();
		os.close();
	}

	/**
	 * Reads the file content from the socket during Download operation.
	 *
	 * @param is
	 * @param fileLocation
	 * @param sessionKey
	 * @param iv
	 * @param msg
	 * @throws ClassNotFoundException
	 * @throws IOException
	 */
	public static boolean receive(ObjectInputStream is, String fileLocation, DownloadMessage msg)
			throws ClassNotFoundException, IOException {
		FileOutputStream fos = new FileOutputStream(fileLocation);
		byte[] pn, receivedMac = new byte[16], bn = md.digest(sessionKey.add(iv).toByteArray());
		BigInteger macSessionKey = sessionKey.add(BigInteger.ONE);
		try {
			for (; !msg.exit; msg = (DownloadMessage) is.readObject()) {
				pn = new byte[msg.fileContents.length];
				for (int i = 0; i < pn.length; i++)
					pn[i] = (byte) (((int) msg.fileContents[i]) ^ ((int) bn[i]));
				System.arraycopy(md.digest(macSessionKey.add(new BigInteger(pn)).toByteArray()), 0, receivedMac, 0, 16);
				if (!Arrays.equals(msg.mac, receivedMac))
					return false;
				fos.write(pn);
				bn = md.digest(sessionKey.add(new BigInteger(msg.fileContents)).toByteArray());
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			fos.flush();
			fos.close();
		}
		return true;
	}

	/**
	 * To validate the filename.
	 *
	 * @param text
	 * @return
	 */
	private boolean isValid(String text) {
		if (text == null || text.trim().length() == 0)
			return false;
		return true;
	}
}
