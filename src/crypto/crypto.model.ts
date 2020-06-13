export type DecryptionParts = {
  /**
   * The encrypted cipher.
   */
  cipher: Buffer;

  /**
   * The GCM Auth Tag
   */
  authTag: Buffer;

  /**
   * The cryptographic salt for PBKDF2.
   */
  salt: Buffer;

  /**
   * The initialization vector for GCM.
   */
  iv: Buffer;
}
