package com.ucoruh.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @file EncryptionUtil.java
 * @class EncryptionUtil
 * @brief Utility class for encryption and decryption operations
 * @author Password Manager Team
 * @version 1.0
 * @details This class provides methods to securely encrypt and decrypt sensitive information
 * like passwords using AES encryption with a key derived from the master password.
 */
public class EncryptionUtil {
  /**
   * @brief The encryption algorithm used (AES)
   */
  private static final String ALGORITHM = "AES";

  /**
   * @brief Encrypts a string using AES encryption
   * @details Uses the master password to derive an encryption key and encrypts the data
   * using AES encryption. The result is encoded in Base64 format.
   *
   * @param data The string to encrypt
   * @param masterPassword The master password used to derive the encryption key
   * @return String The encrypted string in Base64 encoding
   * @throws Exception If encryption fails
   */
  public static String encrypt(String data, String masterPassword) throws Exception {
    SecretKeySpec secretKey = createSecretKey(masterPassword);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(encryptedData);
  }

  /**
   * @brief Decrypts a string that was encrypted using AES encryption
   * @details Uses the master password to derive the decryption key and decrypts
   * the Base64 encoded encrypted data using AES decryption.
   *
   * @param encryptedData The encrypted string in Base64 encoding
   * @param masterPassword The master password used to derive the decryption key
   * @return String The decrypted string
   * @throws Exception If decryption fails
   */
  public static String decrypt(String encryptedData, String masterPassword) throws Exception {
    SecretKeySpec secretKey = createSecretKey(masterPassword);
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    byte[] decodedData = Base64.getDecoder().decode(encryptedData);
    byte[] decryptedData = cipher.doFinal(decodedData);
    return new String(decryptedData, StandardCharsets.UTF_8);
  }

  /**
   * @brief Creates a SecretKeySpec from the master password
   * @details Hashes the master password using SHA-256 and creates an AES key
   * using the first 16 bytes of the hash.
   *
   * @param masterPassword The master password to derive the key from
   * @return SecretKeySpec The generated secret key for AES encryption
   * @throws RuntimeException If the SHA-256 algorithm is not available
   */
  private static SecretKeySpec createSecretKey(String masterPassword) {
    try {
      byte[] key = masterPassword.getBytes(StandardCharsets.UTF_8);
      MessageDigest sha = MessageDigest.getInstance("SHA-256");
      key = sha.digest(key);
      // Use only the first 16 bytes for AES-128
      byte[] shortKey = new byte[16];
      System.arraycopy(key, 0, shortKey, 0, 16);
      return new SecretKeySpec(shortKey, ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error creating encryption key", e);
    }
  }

  /**
   * @brief Hashes a string using SHA-256 algorithm
   * @details Creates a secure hash of the input string using SHA-256 algorithm
   * and returns it in hexadecimal format. This is useful for securely storing
   * the master password.
   *
   * @param input The string to hash
   * @return String The hashed string in hexadecimal format
   * @throws RuntimeException If the SHA-256 algorithm is not available
   */
  public static String hashString(String input) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
      StringBuilder hexString = new StringBuilder();

      for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);

        if (hex.length() == 1) hexString.append('0');

        hexString.append(hex);
      }

      return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error hashing input", e);
    }
  }
}
