package net.eduardolira.blockcipherskip;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.io.InputStream;

public class BlockCipherSkipper {

    private static byte[] singleByte = new byte[1];
    private long bytesDecrypted = 0;
    private Cipher decryptionCipher;

    /**
     * Wrapper around a decryption Cipher to allow skipping blocks when using CBC or CFB modes of operation.
     *
     * @param decryptionCipher a {@link Cipher} initialized with {@link Cipher#DECRYPT_MODE}
     */
    public BlockCipherSkipper(Cipher decryptionCipher) {
        this.decryptionCipher = decryptionCipher;
    }

    /**
     * Static helper method to read from an {@link InputStream} until the buffer is filled or {@link IOException} is thrown
     * @param inputStream stream to read from
     * @param buffer buffer to write to
     * @throws IOException
     */
    private static void hardRead(InputStream inputStream, byte[] buffer) throws IOException {
        int length = buffer.length;
        int totalBytesRead = 0;
        while (totalBytesRead < length) {
            int bytesRead = inputStream.read(buffer, totalBytesRead, length - totalBytesRead);
            if (bytesRead >= 0) totalBytesRead += bytesRead;
        }
    }

    /**
     * Static helper method to drain a number of bytes from an inputstream. Useful when needed to skip to a different
     * location in the stream.
     * @param inputStream stream to drain from
     * @param bytesToDrain amount of bytes to drain
     * @throws IOException
     */
    public static void drainBytes(InputStream inputStream, long bytesToDrain) throws IOException {
        int totalBytesDrained = 0;
        while (totalBytesDrained < bytesToDrain) {
            long bytesDrained = inputStream.skip(bytesToDrain - totalBytesDrained);
            if (bytesDrained >= 0) totalBytesDrained += bytesDrained;
        }
    }

    /**
     * Utility method for decrypting a single byte
     *
     * @param single the byte needed decryption
     * @return
     * @throws ShortBufferException
     */
    public byte decryptSingleByte(byte single) throws ShortBufferException {
        singleByte[0] = single;
        decryptionCipher.update(singleByte, 0, 1, singleByte);
        bytesDecrypted++;
        return singleByte[0];
    }

    /**
     * Decrypts byte array in place, not initializing a new byte array but rather modifying the existing one in place.
     *
     * @param input the byte array to decrypt in place
     * @throws ShortBufferException
     */
    public void decryptInPlace(byte[] input) throws ShortBufferException {
        bytesDecrypted += decryptionCipher.update(input, 0, input.length, input);
    }

    /**
     * Skips lengthToSkip amount of bytes while managing the current position in the Cipher. Disposes of the bytes
     * remaining in the current block, skips a number of blocks, reads the block immediately preceding the target block,
     * then skips the remaining bytes in the target block. By doing this, the cipher keeps a proper feedback block yet
     * still allows skipping large chunks of uneeded data without needing to decrypt it all to get to the desired
     * position in the stream.
     *
     * @param inputStream the stream from where encrypted data is being read
     * @param lengthToskip amount of bytes to skip
     * @throws ShortBufferException
     * @throws IOException
     */
    public void skipDecrypt(InputStream inputStream, int lengthToskip) throws ShortBufferException, IOException {
        //This is too small of a section to skip. Lets read the bytes anyways and toss them since we dont need them
        if (!shouldSkip(lengthToskip)) {
            byte[] bytes = new byte[lengthToskip];
            hardRead(inputStream, bytes);
            decryptInPlace(bytes);
            return;
        }

        //Otherwise lets first finish up this block.
        long inCurrentBlock = bytesLeftInCurrentBlock();
        byte[] readBytes = new byte[(int) inCurrentBlock];
        hardRead(inputStream, readBytes);
        decryptInPlace(readBytes);

        //Now lets figure out how many full blocks we can skip.
        long bytesLeftToSkip = lengthToskip - inCurrentBlock;
        long blockSize = decryptionCipher.getBlockSize();

        //How many bytes over the block delimiter the end is. Val between 0 and blocksize
        long over = (getBytesDecryptedCount() + bytesLeftToSkip) % blockSize;

        //Bytes left to allocate between the end of the current block and the start of the ending block
        //should work out to a multiple of blocksize because of the math.
        long middleBytesToSkip = bytesLeftToSkip - (over + blockSize); //we want to leave an extra block of padding.
        drainBytes(inputStream, (int) middleBytesToSkip);

        //and finally, lets read the preceding block and the bytes in the block that we dont need.
        int bytesToSkip = (int) (over + blockSize);
        byte[] finalReadBuff = new byte[bytesToSkip];
        hardRead(inputStream, finalReadBuff);
        decryptInPlace(finalReadBuff);
    }

    /**
     * Calculates the bytes remaining in the cipher's current block
     * @return amount of bytes left
     */
    private long bytesLeftInCurrentBlock() {
        long blockSize = decryptionCipher.getBlockSize();
        long count = getBytesDecryptedCount();
        return blockSize - (count % blockSize);
    }

    /**
     * Figures whether the requested amount of bytes can be skipped. The skip method can only really skip encrypting n-1
     * whole blocks where n is the amount of whole blocks between the current position and the target location.
     * This method calculates whether it can't or can process a real skip with the given cipher and parameters.
     * @param bytesToskip
     * @return whether or not a real skip can be done
     */
    private boolean shouldSkip(long bytesToskip) {
        long blockSize = decryptionCipher.getBlockSize();

        long currBlockRemaining = bytesLeftInCurrentBlock();
        //How many bytes over the block delimiter the end is. Val between 0 and blocksize
        long over = getBytesDecryptedCount() + bytesToskip % blockSize;

        return bytesToskip <= (currBlockRemaining + blockSize + over);
    }

    protected long bytesNeededToSkip(long bytesToskip) {
        long blockSize = decryptionCipher.getBlockSize();

        long currBlockRemaining = bytesLeftInCurrentBlock();

        //How many bytes over the block delimiter the end is. Val between 0 and blocksize
        long over = getBytesDecryptedCount() + bytesToskip % blockSize;

        if (bytesToskip <= (currBlockRemaining + blockSize + over))
            return 0;

        //Bytes left to allocate between the end of the current block and the start of the ending block
        //should work out to a multiple of blocksize because of the math.
        long bytesLeftToAllocate = bytesToskip - (over + currBlockRemaining);

        long middleBytesToSkip = bytesLeftToAllocate - blockSize;

        return currBlockRemaining + middleBytesToSkip;
    }

    private long getBytesDecryptedCount() {
        return bytesDecrypted;
    }

}
