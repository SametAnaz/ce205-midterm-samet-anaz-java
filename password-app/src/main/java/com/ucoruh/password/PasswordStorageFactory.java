package com.ucoruh.password;

/**
 * @file PasswordStorageFactory.java
 * @class PasswordStorageFactory
 * @brief Factory class to create password storage implementations.
 * @author Password Manager Team
 * @version 1.0
 *
 * This class provides a static factory method to return an appropriate instance of
 * InterfacePasswordStorage based on the provided storage type. It supports different
 * storage implementations such as file-based storage and SQLite-based storage.
 */
public class PasswordStorageFactory {

  /**
   * @brief Returns a password storage implementation based on the selected type.
   *
   * This method uses a switch expression to determine which implementation of
   * InterfacePasswordStorage to instantiate depending on the given storage type.
   * It passes the master password to the storage implementation for encryption/decryption.
   *
   * @param type The storage type (e.g., FILE, SQLITE, etc.).
   * @param masterPassword The master password for encryption/decryption.
   * @return An instance of InterfacePasswordStorage corresponding to the provided storage type.
   */
  public static InterfacePasswordStorage create(StorageType type, String masterPassword) {

    return switch (type) {
      case FILE -> new FilePasswordStorage(masterPassword);

      case SQLITE -> new DatabasePasswordStorage(masterPassword);
    };
  }
}
