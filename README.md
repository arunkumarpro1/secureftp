# secureftp
This project is a design and implementation of a secure Internet file transfer application/protocol. The application will include a client and a server. The program includes several security requirements as outlined below. 

**Supported Functionality**
--------------------------
• Client can upload files to the server in a secure fashion. Client can also download files from server in a secure fashion.

• When the file is uploaded, or downloaded, it is intact, i.e. the features are retained. For instance, if it is executable, you will be able to run it, or if it is an image, the image is same as the original file.

• Client only needs to authenticate the server. The server need not authenticate client.

• The application only uses keyed hash, e.g. SHA-3 for securing the communication.

• The security requirements satisfied by this application and other details are clearly explained in the [design document](https://github.com/arunkumarpro1/secureftp/blob/master/Project%20Design%20Report.docx).
