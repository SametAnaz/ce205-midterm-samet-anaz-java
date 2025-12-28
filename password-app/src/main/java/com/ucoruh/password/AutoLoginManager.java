/**
 * @file AutoLoginManager.java
 * @class AutoLoginManager
 * @brief Manages auto-login functionality for the password manager
 * @author Password Manager Team
 * @version 1.0
 * @details This class manages auto-login settings for different services and provides
 * methods to enable or disable auto-login functionality for specific accounts.
 */
package com.ucoruh.password;

import java.io.*;
import java.util.*;

/**
 * @brief Manages auto-login settings for password entries.
 * @details This class provides functionality to enable or disable auto-login for specific services
 * and maintains a collection of services for which auto-login is enabled.
 */
public class AutoLoginManager {
  /**
   * @brief File path for storing auto-login settings
   */
  private static final String AUTO_LOGIN_FILE = "autologin.txt";

  /**
   * @brief Set of services with auto-login enabled
   */
  private static Set<String> autoLoginServices = new HashSet<>();

  /**
   * @brief Flag indicating if the manager has been initialized
   */
  private static boolean initialized = false;

  /**
   * @brief Initializes the AutoLoginManager
   * @details Loads the auto-login settings from the file if it exists.
   * This method is called internally before any operation.
   */
  private static void initialize() {
    if (initialized) return;

    try (BufferedReader reader = new BufferedReader(new FileReader(AUTO_LOGIN_FILE))) {
      String line;

      while ((line = reader.readLine()) != null) {
        autoLoginServices.add(line.trim());
      }
    } catch (IOException e) {
      // File might not exist yet, that's OK
    }

    initialized = true;
  }

  /**
   * @brief Saves the current auto-login settings
   * @details Writes the current auto-login settings to the configuration file.
   * Called after any modification to the settings.
   */
  private static void saveSettings() {
    try (PrintWriter writer = new PrintWriter(new FileWriter(AUTO_LOGIN_FILE))) {
      for (String service : autoLoginServices) {
        writer.println(service);
      }
    } catch (IOException e) {
      System.out.println("Error saving auto-login settings: " + e.getMessage());
    }
  }

  /**
   * @brief Checks if auto-login is enabled for a service
   * @details Verifies whether the specified service has auto-login enabled
   * by checking the autoLoginServices set.
   *
   * @param service The service name to check
   * @return boolean True if auto-login is enabled, false otherwise
   */
  public static boolean isAutoLoginEnabled(String service) {
    initialize();
    return autoLoginServices.contains(service);
  }

  /**
   * @brief Enables auto-login for a service
   * @details Adds the specified service to the auto-login enabled set
   * and saves the updated settings.
   *
   * @param service The service name to enable auto-login for
   */
  public static void enableAutoLogin(String service) {
    initialize();
    autoLoginServices.add(service);
    saveSettings();
  }

  /**
   * @brief Disables auto-login for a service
   * @details Removes the specified service from the auto-login enabled set
   * and saves the updated settings.
   *
   * @param service The service name to disable auto-login for
   */
  public static void disableAutoLogin(String service) {
    initialize();
    autoLoginServices.remove(service);
    saveSettings();
  }

  /**
   * @brief Performs auto-login for a service
   * @details Attempts to automatically log in to the specified service
   * if auto-login is enabled and credentials are available.
   *
   * @param service The service name to auto-login to
   * @param passwordManager The PasswordManager instance containing credentials
   * @return boolean True if auto-login was successful, false otherwise
   */
  public static boolean autoLogin(String service, PasswordManager passwordManager) {
    if (isAutoLoginEnabled(service)) {
      String password = passwordManager.getCredential(service);

      if (password != null) {
        System.out.println("Auto-logging in to " + service + "...");
        // Simulate login
        System.out.println("Successfully logged in to " + service);
        return true;
      }
    }

    return false;
  }

  /**
   * @brief Displays and handles the auto-login menu
   * @details Shows the auto-login management menu and processes user input
   * for various auto-login operations.
   *
   * @param scanner Scanner object for reading user input
   * @param passwordManager The PasswordManager instance to use for credentials
   */
  public static void menu(Scanner scanner, PasswordManager passwordManager) {
    initialize();
    boolean back = false;

    while (!back) {
      System.out.println("\n==== AUTO-LOGIN FEATURES ====");
      System.out.println("1. Enable Auto-Login for a service");
      System.out.println("2. Disable Auto-Login for a service");
      System.out.println("3. Show services with Auto-Login enabled");
      System.out.println("4. Simulate Auto-Login for a service");
      System.out.println("0. Back to Main Menu");
      System.out.print("Your choice: ");
      String input = scanner.nextLine();

      try {
        int choice = Integer.parseInt(input);

        switch (choice) {
          case 1:
            enableAutoLoginMenu(scanner, passwordManager);
            break;

          case 2:
            disableAutoLoginMenu(scanner);
            break;

          case 3:
            showAutoLoginServices();
            break;

          case 4:
            simulateAutoLogin(scanner, passwordManager);
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

  /**
   * @brief Handles the enable auto-login menu option
   * @details Prompts for a service name and enables auto-login if the service
   * exists in the password manager.
   *
   * @param scanner Scanner object for reading user input
   * @param passwordManager The PasswordManager instance to verify service existence
   */
  private static void enableAutoLoginMenu(Scanner scanner, PasswordManager passwordManager) {
    System.out.print("Enter service name to enable auto-login: ");
    String service = scanner.nextLine();

    // Check if the service exists in the password manager
    if (passwordManager.getCredential(service) != null) {
      enableAutoLogin(service);
      System.out.println("Auto-login enabled for " + service);
    } else {
      System.out.println("Service not found. Please add this service to your passwords first.");
    }
  }

  /**
   * @brief Handles the disable auto-login menu option
   * @details Prompts for a service name and disables auto-login if it was
   * previously enabled.
   *
   * @param scanner Scanner object for reading user input
   */
  private static void disableAutoLoginMenu(Scanner scanner) {
    System.out.print("Enter service name to disable auto-login: ");
    String service = scanner.nextLine();

    if (isAutoLoginEnabled(service)) {
      disableAutoLogin(service);
      System.out.println("Auto-login disabled for " + service);
    } else {
      System.out.println("Auto-login was not enabled for " + service);
    }
  }

  /**
   * @brief Shows all services with auto-login enabled
   * @details Displays a list of all services that currently have
   * auto-login enabled.
   */
  private static void showAutoLoginServices() {
    initialize();
    System.out.println("\nServices with Auto-Login enabled:");

    if (autoLoginServices.isEmpty()) {
      System.out.println("None");
    } else {
      for (String service : autoLoginServices) {
        System.out.println("- " + service);
      }
    }
  }

  /**
   * @brief Simulates auto-login for a specified service
   * @details Prompts for a service name and attempts to perform
   * auto-login using the stored credentials.
   *
   * @param scanner Scanner object for reading user input
   * @param passwordManager The PasswordManager instance to use for credentials
   */
  private static void simulateAutoLogin(Scanner scanner, PasswordManager passwordManager) {
    System.out.print("Enter service name to auto-login: ");
    String service = scanner.nextLine();

    if (!autoLogin(service, passwordManager)) {
      System.out.println("Auto-login failed for " + service);
    }
  }
}
