package com.ucoruh.password;

import java.sql.*;
import java.util.*;

/**
 * @file DatabasePasswordStorage.java
 * @class DatabasePasswordStorage
 * @brief SQLite-based implementation of password storage.
 * @author Password Manager Team
 * @version 1.0
 *
 * This class uses an SQLite database to store, retrieve, update, and delete password entries.
 * All sensitive data is encrypted before storing in the database.
 */
public class DatabasePasswordStorage implements InterfacePasswordStorage {
  /**
   * @brief The database URL for the SQLite connection.
   *
   * This static final field holds the connection URL used to connect to the SQLite database.
   */
  private static final String DB_URL = "jdbc:sqlite:passwords.db";

  /**
   * @brief The master password used for encryption/decryption.
   */
  private final String masterPassword;

  /**
   * @brief Constructs a DatabasePasswordStorage object and initializes the database.
   *
   * @param masterPassword The master password for encryption/decryption.
   */
  public DatabasePasswordStorage(String masterPassword) {
    this.masterPassword = masterPassword;
    createTableIfNotExists();
  }

  /**
   * @brief Retrieves the database URL for the SQLite connection.
   *
   * @return A string containing the SQLite database URL.
   */
  protected String getDatabaseUrl() {
    return DB_URL;
  }

  /**
   * @brief Creates the passwords table in the database if it does not already exist.
   *
   * This method executes an SQL statement to initialize the database structure required
   * to store password entries.
   */
  private void createTableIfNotExists() {
    try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
           Statement stmt = conn.createStatement()) {
      String sql = """
                   CREATE TABLE IF NOT EXISTS passwords (
                     service TEXT PRIMARY KEY,
                     username TEXT NOT NULL,
                     password TEXT NOT NULL
                   )
                   """;
                   stmt.execute(sql);
    } catch (SQLException e) {
      System.out.println("Error initializing database: " + e.getMessage());
    }
  }

  /**
   * @brief Adds a new password entry to the database using user input.
   *
   * This method reads service, username, and password from the provided Scanner,
   * encrypts the sensitive data, and inserts the new entry into the passwords table.
   *
   * @param scanner the Scanner object used to obtain user input.
   */
  @Override
  public void add(Scanner scanner) {
    System.out.print("Service: ");
    String service = scanner.nextLine();
    System.out.print("Username: ");
    String user = scanner.nextLine();
    System.out.print("Password: ");
    String pass = scanner.nextLine();

    try {
      // Check if service already exists
      try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
             PreparedStatement pstmt = conn.prepareStatement(
                                         "SELECT 1 FROM passwords WHERE service = ?")) {
        pstmt.setString(1, service);

        try (ResultSet rs = pstmt.executeQuery()) {
          if (rs.next()) {
            System.out.println("A password for this service already exists. Use update option to modify it.");
            return;
          }
        }
      }

      // Encrypt username and password
      String encryptedUser = EncryptionUtil.encrypt(user, masterPassword);
      String encryptedPass = EncryptionUtil.encrypt(pass, masterPassword);

      // Insert new record
      try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
             PreparedStatement pstmt = conn.prepareStatement(
                                         "INSERT INTO passwords(service, username, password) VALUES(?, ?, ?)")) {
        pstmt.setString(1, service);
        pstmt.setString(2, encryptedUser);
        pstmt.setString(3, encryptedPass);
        pstmt.executeUpdate();
        System.out.println("Password saved successfully.");
      }
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    } catch (Exception e) {
      System.out.println("Encryption error: " + e.getMessage());
    }
  }

  /**
   * @brief Retrieves and displays all password entries from the database.
   *
   * This method executes an SQL query to obtain all records from the passwords table,
   * decrypts the sensitive data, and prints each entry using the Password class's toString() method.
   */
  @Override
  public void view() {
    try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
           Statement stmt = conn.createStatement();
           ResultSet rs = stmt.executeQuery("SELECT * FROM passwords")) {
      int count = 0;

      while (rs.next()) {
        try {
          String service = rs.getString("service");
          String encryptedUsername = rs.getString("username");
          String encryptedPassword = rs.getString("password");
          // Decrypt username and password
          String username = EncryptionUtil.decrypt(encryptedUsername, masterPassword);
          String password = EncryptionUtil.decrypt(encryptedPassword, masterPassword);
          count++;
          System.out.println(count + ". " + new Password(service, username, password));
        } catch (Exception e) {
          System.out.println("Error decrypting entry: " + e.getMessage());
        }
      }

      if (count == 0) {
        System.out.println("No records found.");
      }
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    }
  }

  /**
   * @brief Updates an existing password entry in the database with new username and password.
   *
   * This method prompts the user for the service to update, along with the new username
   * and password, encrypts the sensitive data, and then updates the corresponding record in the database.
   *
   * @param scanner the Scanner object used to obtain user input.
   */
  @Override
  public void update(Scanner scanner) {
    System.out.print("Service to update: ");
    String service = scanner.nextLine();

    try {
      // Check if service exists and get current values
      String currentUsername = null;

      try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
             PreparedStatement pstmt = conn.prepareStatement(
                                         "SELECT username FROM passwords WHERE service = ?")) {
        pstmt.setString(1, service);

        try (ResultSet rs = pstmt.executeQuery()) {
          if (rs.next()) {
            String encryptedUsername = rs.getString("username");
            currentUsername = EncryptionUtil.decrypt(encryptedUsername, masterPassword);
          } else {
            System.out.println("Service not found.");
            return;
          }
        }
      }

      System.out.print("New username (leave blank to keep current '" + currentUsername + "'): ");
      String username = scanner.nextLine();

      if (username.trim().isEmpty()) {
        username = currentUsername;
      }

      System.out.print("New password (leave blank to keep current): ");
      String password = scanner.nextLine();
      // Encrypt the new values
      String encryptedUsername = EncryptionUtil.encrypt(username, masterPassword);

      if (password.trim().isEmpty()) {
        // Only update username
        try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
               PreparedStatement pstmt = conn.prepareStatement(
                                           "UPDATE passwords SET username = ? WHERE service = ?")) {
          pstmt.setString(1, encryptedUsername);
          pstmt.setString(2, service);
          pstmt.executeUpdate();
        }
      } else {
        // Update both username and password
        String encryptedPassword = EncryptionUtil.encrypt(password, masterPassword);

        try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
               PreparedStatement pstmt = conn.prepareStatement(
                                           "UPDATE passwords SET username = ?, password = ? WHERE service = ?")) {
          pstmt.setString(1, encryptedUsername);
          pstmt.setString(2, encryptedPassword);
          pstmt.setString(3, service);
          pstmt.executeUpdate();
        }
      }

      System.out.println("Password updated successfully.");
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    } catch (Exception e) {
      System.out.println("Encryption error: " + e.getMessage());
    }
  }

  /**
   * @brief Deletes a password entry from the database based on the service name.
   *
   * This method prompts the user for the service of the entry to delete and removes the
   * corresponding record from the database.
   *
   * @param scanner the Scanner object used to obtain user input.
   */
  @Override
  public void delete(Scanner scanner) {
    System.out.print("Service to delete: ");
    String service = scanner.nextLine();

    try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
           PreparedStatement pstmt = conn.prepareStatement("DELETE FROM passwords WHERE service = ?")) {
      pstmt.setString(1, service);
      int affected = pstmt.executeUpdate();

      if (affected > 0) {
        System.out.println("Password deleted successfully.");
      } else {
        System.out.println("Service not found.");
      }
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    }
  }

  /**
   * @brief Reads all password entries from the database.
   *
   * This method retrieves all records from the passwords table, decrypts the sensitive data,
   * converts each record into a Password object, and returns a list of these objects.
   *
   * @return A List of Password objects representing all stored password entries.
   */
  @Override
  public List<Password> readAll() {
    List<Password> list = new ArrayList<>();

    try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
           Statement stmt = conn.createStatement();
           ResultSet rs = stmt.executeQuery("SELECT * FROM passwords")) {
      while (rs.next()) {
        try {
          String service = rs.getString("service");
          String encryptedUsername = rs.getString("username");
          String encryptedPassword = rs.getString("password");
          // Decrypt username and password
          String username = EncryptionUtil.decrypt(encryptedUsername, masterPassword);
          String password = EncryptionUtil.decrypt(encryptedPassword, masterPassword);
          list.add(new Password(service, username, password));
        } catch (Exception e) {
          System.out.println("Error decrypting entry: " + e.getMessage());
        }
      }
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    }

    return list;
  }

  /**
   * @brief Writes a list of password entries to the database.
   *
   * This method clears the existing contents of the passwords table and inserts all password entries
   * from the provided list, encrypting sensitive data before storage.
   *
   * @param list A List of Password objects to be written to the database.
   */
  @Override
  public void writeAll(List<Password> list) {
    try (Connection conn = DriverManager.getConnection(getDatabaseUrl());
           Statement stmt = conn.createStatement()) {
      stmt.execute("DELETE FROM passwords"); // clear all

      for (Password p : list) {
        try {
          // Encrypt username and password
          String encryptedUsername = EncryptionUtil.encrypt(p.getUsername(), masterPassword);
          String encryptedPassword = EncryptionUtil.encrypt(p.getPassword(), masterPassword);

          try (PreparedStatement pstmt = conn.prepareStatement(
                                             "INSERT INTO passwords(service, username, password) VALUES (?, ?, ?)")) {
            pstmt.setString(1, p.getService());
            pstmt.setString(2, encryptedUsername);
            pstmt.setString(3, encryptedPassword);
            pstmt.executeUpdate();
          }
        } catch (Exception e) {
          System.out.println("Error encrypting data for " + p.getService() + ": " + e.getMessage());
        }
      }
    } catch (SQLException e) {
      System.out.println("Database error: " + e.getMessage());
    }
  }
}
