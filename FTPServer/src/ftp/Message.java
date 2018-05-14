package ftp;

import java.io.Serializable;

public class Message implements Serializable {
	private static final long serialVersionUID = 1363477356636719729L;
	String message;
	byte[] mac = new byte[16];
	boolean exit = false;

	public Message(String message) {
		this.message = message;
	}
}

class UploadMessage extends Message {
	private static final long serialVersionUID = 3318073711426485941L;
	byte[] fileContents;

	public UploadMessage(String filename, byte[] fileContents) {
		super(filename);
		this.fileContents = fileContents;
	}
}

class DownloadMessage extends Message {
	private static final long serialVersionUID = -6684893361847107726L;
	byte[] fileContents;

	public DownloadMessage(String filename, byte[] fileContents) {
		super(filename);
		this.fileContents = fileContents;
	}
}

class SessionKeyMessage extends Message {
	private static final long serialVersionUID = -1308883786322216984L;
	byte[] encryptedSessionKey;
	byte[] encryptedIV;

	public SessionKeyMessage(String message) {
		super(message);
	}

}
