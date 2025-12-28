package com.ucoruh.password;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

/**
 * @file AuthManager.java
 * @class AuthManager
 * @brief Singleton class that manages user authentication.
 * @author Password Manager Team
 * @version 1.0
 *
 * This class handles the creation and verification of the master password.
 * It also provides a stub for user-specific functionality.
 */
public class AuthManager {
  /**
   * @brief Singleton instance of the AuthManager.
   *
   * This static field holds the single instance of the AuthManager
   * used throughout the application to ensure consistent user authentication.
   */
  private static AuthManager instance;

  /**
   * @brief Master password used for authentication.
   *
   * This field stores the master password that is used to authenticate the user.
   */
  private String masterPassword;  // Stores master password

  /**
   * @brief File where the hashed master password is stored.
   */
  private static final String MASTER_PASSWORD_FILE = "master-password.txt";

  /**
   * Private constructor to enforce singleton pattern.
   * Attempts to load the master password from file if it exists.
   */
  private AuthManager() {
    loadMasterPassword();
  }

  /**
   * Retrieve the singleton instance.
   * @return AuthManager instance.
   */
  public static AuthManager getInstance() {
    if (instance == null) {
      instance = new AuthManager();
    }

    return instance;
  }

  /**
   * Resets the singleton instance.
   * <p>
   * This method is intended for testing purposes only.
   * </p>
   */
  public static void resetInstance() {
    instance = null;
  }

  /**
   * Loads the master password from file.
   */
  private void loadMasterPassword() {
    File file = new File(MASTER_PASSWORD_FILE);

    if (file.exists()) {
      try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
        masterPassword = reader.readLine();
      } catch (IOException e) {
        System.out.println("Error loading master password: " + e.getMessage());
      }
    }
  }

  /**
   * Saves the master password to file.
   */
  private void saveMasterPassword() {
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(MASTER_PASSWORD_FILE))) {
      writer.write(masterPassword);
    } catch (IOException e) {
      System.out.println("Error saving master password: " + e.getMessage());
    }
  }

  /**
   * Check if the master password is set.
   * @return true if master password is set; otherwise false.
   */
  public boolean isMasterPasswordSet() {
    return masterPassword != null && !masterPassword.isEmpty();
  }

  /**
   * Create the master password.
   * @param scanner The Scanner object for user input.
   */
  public void createMasterPassword(Scanner scanner) {
    String input = scanner.nextLine();
    masterPassword = EncryptionUtil.hashString(input);
    saveMasterPassword();
    System.out.println("Master password set successfully.");
  }

  /**
   * Perform user login.
   * @param scanner The Scanner object for user input.
   * @return true if login is successful.
   */
  public boolean login(Scanner scanner) {
    String input = scanner.nextLine();
    String hashedInput = EncryptionUtil.hashString(input);
    boolean success = masterPassword.equals(hashedInput);

    if (success) {
      // Store the plaintext password for encryption/decryption operations
      masterPassword = input;
    }

    return success;
  }

  /**
   * Getter for the master password.
   * @return The master password.
   */
  public String getMasterPassword() {
    return masterPassword;
  }

  /**
   * Change the master password.
   * @param scanner The Scanner object for user input.
   * @return true if password change is successful.
   */
  public boolean changeMasterPassword(Scanner scanner) {
    System.out.print("Enter current master password: ");
    String currentPassword = scanner.nextLine();
    String hashedCurrent = EncryptionUtil.hashString(currentPassword);

    // Verify the current password before allowing a change
    if (!masterPassword.equals(hashedCurrent) && !masterPassword.equals(currentPassword)) {
      System.out.println("Incorrect current password.");
      return false;
    }

    System.out.print("Enter new master password: ");
    String newPassword = scanner.nextLine();
    System.out.print("Confirm new master password: ");
    String confirmPassword = scanner.nextLine();

    if (!newPassword.equals(confirmPassword)) {
      System.out.println("Passwords do not match.");
      return false;
    }

    masterPassword = EncryptionUtil.hashString(newPassword);
    saveMasterPassword();
    System.out.println("Master password changed successfully.");
    return true;
  }

  /**
   * Display user-specific menu for authentication operations.
   * @param scanner The Scanner object for user input.
   */
  public void userMenu(Scanner scanner) {
    boolean back = false;

    while (!back) {
      System.out.println("\n==== USER AUTHENTICATION MENU ====");
      System.out.println("1. Change Master Password");
      System.out.println("2. Test Authentication");
      System.out.println("0. Back to Main Menu");
      System.out.print("Your choice: ");
      String input = scanner.nextLine();

      try {
        int choice = Integer.parseInt(input);

        switch (choice) {
          case 1:
            changeMasterPassword(scanner);
            break;

          case 2:
            System.out.print("Enter master password to verify: ");
            String testPassword = scanner.nextLine();
            String hashedTest = EncryptionUtil.hashString(testPassword);

            if (masterPassword.equals(hashedTest) || masterPassword.equals(testPassword)) {
              System.out.println("Authentication successful.");
            } else {
              System.out.println("Authentication failed.");
            }

            break;

          case 0:
            back = true;
            break;

          default:
            System.out.println("Invalid choice.");
            break;
        }
      } catch (NumberFormatException e) {
        System.out.println("Invalid number.");
      }
    }
  }
}
