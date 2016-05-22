# BlockCipherSkip
Wrapper around a decryption Cipher to allow skipping blocks when using CBC or CFB modes of operation.

Skips an arbitrary amount of bytes while managing the current position in the Cipher. Disposes of the bytes
remaining in the current block, skips a number of blocks, reads the block immediately preceding the target block,
then skips the remaining bytes in the target block. By doing this, the cipher keeps a proper feedback block yet
still allows skipping large chunks of unneeded data without needing to decrypt it all to get to the desired
position in the stream.

In the example in main() AES Ciphers operating in CBF8/NoPadding mode are used.  
Sample Output
---------
  Without proper CFB skipping:  
> Hello t��~�
  
  Using CFBSkipper  
> Hello World!
