package com.ucoruh.password;

/**
 * @file StorageType.java
 * @enum StorageType
 * @brief Enum for supported storage types.
 * @author Password Manager Team
 * @version 1.0
 *
 * This enum defines the types of storage available for password storage,
 * including file-based and SQLite-based implementations.
 */
public enum StorageType {
  /**
   * @brief Represents file-based storage.
   */
  FILE,

  /**
   * @brief Represents SQLite-based storage.
   */
  SQLITE
}
