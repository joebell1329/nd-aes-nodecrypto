import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

import { DecryptionParts } from './crypto.model';

export class CryptoService {

  /**
   * A 128 bit salt is recommended by NIST for PBKDF2
   * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
   */
  private static readonly SALT_LENGTH = 16;

  /**
   * For AES GCM, the strongly recommended IV length is 96 bits as longer IV's can lead to collisions.
   * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
   */
  private static readonly IV_LENGTH = 12;

  /**
   * The length of the GCM Auth Tag
   */
  private static readonly AUTH_TAG_LENGTH = 16;

  /**
   * The minimum recommended PBKDF2 iterations by OWASP
   * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
   */
  private static readonly DEFAULT_PBKDF2_ITERATIONS = 10000;

  public static encrypt(data: string, password: string, pbkdf2Iterations?: number): string {
    const salt = randomBytes(this.SALT_LENGTH);
    const iv = randomBytes(this.IV_LENGTH);

    const derivedKey = CryptoService.getDerivedKey(password, salt, pbkdf2Iterations || CryptoService.DEFAULT_PBKDF2_ITERATIONS);
    const cipher = createCipheriv('aes-256-gcm', derivedKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const encryptedBuffer = Buffer.concat([salt, iv, encrypted, authTag]);

    return encryptedBuffer.join(' ');
  }

  public static decrypt(encryptedData: string, password: string, pbkdf2Iterations?: number): string {
    const { salt, iv, cipher, authTag } = CryptoService.extractDecryptionParts(encryptedData);
    const derivedKey = CryptoService.getDerivedKey(password, salt, pbkdf2Iterations || CryptoService.DEFAULT_PBKDF2_ITERATIONS);
    const decipher = createDecipheriv('aes-256-gcm', derivedKey, iv);
    decipher.setAuthTag(authTag);

    const decryptedBuffer = Buffer.concat([decipher.update(cipher), decipher.final()]);

    return decryptedBuffer.toString('utf8');
  }

  private static getDerivedKey(cryptoKey: string, salt: Buffer, iterations: number): Buffer {
    return pbkdf2Sync(cryptoKey, salt, iterations, 32, 'sha256');
  }

  private static extractDecryptionParts(encryptedData: string): DecryptionParts {
    const dataArr = new Uint8Array(encryptedData.split(' ').map(c => parseInt(c, 10)));

    const salt = Buffer.from(dataArr.slice(0, CryptoService.SALT_LENGTH));
    const iv = Buffer.from(dataArr.slice(CryptoService.SALT_LENGTH, CryptoService.SALT_LENGTH + CryptoService.IV_LENGTH));
    const cipherWithTag = dataArr.slice(CryptoService.SALT_LENGTH + CryptoService.IV_LENGTH);
    const cipherLength = cipherWithTag.length - this.AUTH_TAG_LENGTH;
    const cipher = Buffer.from(cipherWithTag.slice(0, cipherLength));
    const authTag = Buffer.from(cipherWithTag.slice(cipherLength));

    return { salt, iv, cipher, authTag };
  }

}
