package com.ucoruh.password;

import java.util.List;
import java.util.Scanner;

/**
 * @file InterfacePasswordStorage.java
 * @interface InterfacePasswordStorage
 * @brief Interface for password storage operations.
 * @author Password Manager Team
 * @version 1.0
 *
 * This interface defines the operations required for handling password storage,
 * including adding, viewing, updating, deleting, reading, and writing password entries.
 */
public interface InterfacePasswordStorage {

  /**
   * @brief Adds a new password entry.
   *
   * This method reads input from the user using the provided Scanner and adds a new password entry.
   *
   * @param scanner Scanner for user input.
   */
  void add(Scanner scanner);

  /**
   * @brief Displays all saved password entries.
   *
   * This method retrieves and displays all password entries stored in the system.
   */
  void view();

  /**
   * @brief Updates an existing password entry.
   *
   * This method allows the user to update an existing password entry by specifying new details.
   *
   * @param scanner Scanner for user input.
   */
  void update(Scanner scanner);

  /**
   * @brief Deletes a password entry.
   *
   * This method deletes a password entry based on user input obtained via the provided Scanner.
   *
   * @param scanner Scanner for user input.
   */
  void delete(Scanner scanner);

  /**
   * @brief Reads all saved password entries.
   *
   * Retrieves all saved password entries from the underlying storage.
   *
   * @return A list of Password entries.
   */
  List<Password> readAll();

  /**
   * @brief Writes all password entries to the storage.
   *
   * This method writes the provided list of password entries to the underlying storage,
   * replacing any existing entries.
   *
   * @param list List of Password entries.
   */
  void writeAll(List<Password> list);
}
