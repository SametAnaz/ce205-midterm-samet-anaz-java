package com.ucoruh.password;

import java.io.PrintStream;
import java.util.Scanner;

/**
 * @file PasswordApp.java
 * @class PasswordApp
 * @brief Entry point for the Password Manager console application.
 * @author Password Manager Team
 * @version 1.0
 *
 * This class provides the main method for launching the application and a runApp method
 * which handles the overall flow of the application including authentication and menu operations.
 */
public class PasswordApp {
  /**
   * @brief Runs the application using the provided Scanner and PrintStream.
   *
   * This method initializes user authentication and starts the main menu loop for handling
   * various operations like user authentication, secure storage of passwords, password generation,
   * auto-login feature, and platform management.
   *
   * @param scanner The Scanner object for user input.
   * @param out The PrintStream object for output.
   */
  public static void runApp(Scanner scanner, PrintStream out) {
    AuthManager auth = AuthManager.getInstance();

    if (!auth.isMasterPasswordSet()) {
      out.print("Set master password: ");
      auth.createMasterPassword(scanner);
    }

    out.print("Enter master password to login: ");

    if (auth.login(scanner)) {
      PasswordManager pm = new PasswordManager(auth.getMasterPassword());
      int choice = -1;

      do {
        out.println("\n==== MAIN MENU ====");
        out.println("1. User Authentication");
        out.println("2. Secure Storage of Passwords");
        out.println("3. Password Generator");
        out.println("4. Auto-Login Feature");
        out.println("5. Multi-Platform Compatibility");
        out.println("0. Exit");
        out.print("Your choice: ");
        String input = scanner.nextLine();

        try {
          choice = Integer.parseInt(input);
        } catch (NumberFormatException e) {
          out.println("Invalid number.");
          continue;
        }

        switch (choice) {
          case 1:
            auth.userMenu(scanner);
            break;

          case 2:
            pm.menu(scanner, out);
            break;

          case 3:
            passwordGeneratorMenu(scanner, out);
            break;

          case 4:
            AutoLoginManager.menu(scanner, pm);
            break;

          case 5:
            platformMenu(scanner, out);
            break;

          case 0:
            out.println("Exiting...");
            break;

          default:
            out.println("Invalid choice.");
            break;
        }
      } while (choice != 0);
    } else {
      out.println("Login failed.");
    }
  }

  /**
   * @brief Displays the password generator menu and processes user input.
   *
   * @param scanner The Scanner object for user input.
   * @param out The PrintStream object for output.
   */
  private static void passwordGeneratorMenu(Scanner scanner, PrintStream out) {
    out.println("\n==== PASSWORD GENERATOR ====");
    out.print("Enter desired password length: ");

    try {
      int length = Integer.parseInt(scanner.nextLine());

      if (length <= 0) {
        out.println("Password length must be greater than 0.");
        return;
      }

      String password = PasswordGenerator.generatePassword(length);
      out.println("Generated Password: " + password);
    } catch (NumberFormatException e) {
      out.println("Invalid number.");
    }
  }

  /**
   * @brief Displays the platform compatibility menu and processes user input.
   *
   * @param scanner The Scanner object for user input.
   * @param out The PrintStream object for output.
   */
  private static void platformMenu(Scanner scanner, PrintStream out) {
    out.println("\n==== PLATFORM COMPATIBILITY ====");
    out.println("This password manager is compatible with the following platforms:");
    out.println("1. Windows");
    out.println("2. macOS");
    out.println("3. Linux");
    out.println("4. Android");
    out.println("5. iOS");
    out.print("\nPress Enter to continue...");
    scanner.nextLine();
  }

  /**
   * @brief Main method to launch the console application.
   *
   * This method serves as the entry point to the application and initiates the runApp method.
   *
   * @param args Command-line arguments (not used).
   */
  public static void main(String[] args) {
    // Check whether to start in GUI mode
    boolean useGUI = !isConsoleMode(args);

    if (useGUI) {
      startGUIMode();
    } else {
      // Start in console mode
      Scanner scanner = new Scanner(System.in);
      runApp(scanner, System.out);
      scanner.close();
    }
  }

  /**
   * @brief Checks if console mode is requested via command line arguments.
   *
   * @param args Command-line arguments
   * @return true if console mode is requested, false otherwise
   */
  static boolean isConsoleMode(String[] args) {
    for (String arg : args) {
      if (arg.equalsIgnoreCase("--console") || arg.equalsIgnoreCase("-c")) {
        return true;
      }
    }

    return false;
  }

  /**
   * @brief Starts the application in GUI mode.
   */
  static void startGUIMode() {
    // Start in GUI mode
    setupLookAndFeel();
    java.awt.EventQueue.invokeLater(new Runnable() {
      public void run() {
        createAndShowGUI();
      }
    });
  }

  /**
   * @brief Sets up the system look and feel for the GUI.
   */
  static void setupLookAndFeel() {
    try {
      // Set system look and feel
      javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName());
      // Font settings
      java.awt.Font defaultFont = new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, 14);
      javax.swing.UIManager.put("Button.font", defaultFont);
      javax.swing.UIManager.put("Label.font", defaultFont);
      javax.swing.UIManager.put("TextField.font", defaultFont);
      javax.swing.UIManager.put("PasswordField.font", defaultFont);
      javax.swing.UIManager.put("TextArea.font", defaultFont);
      javax.swing.UIManager.put("ComboBox.font", defaultFont);
      javax.swing.UIManager.put("CheckBox.font", defaultFont);
      javax.swing.UIManager.put("RadioButton.font", defaultFont);
    } catch (Exception e) {
      // Log but continue - default look and feel will be used
      System.err.println("Could not set look and feel: " + e.getMessage());
    }
  }

  /**
   * @brief Creates and shows the GUI frame.
   */
  static void createAndShowGUI() {
    try {
      com.ucoruh.password.gui.PasswordManagerGUI frame = new com.ucoruh.password.gui.PasswordManagerGUI();
      frame.setVisible(true);
    } catch (Exception e) {
      System.err.println("Could not create GUI: " + e.getMessage());
    }
  }
}
