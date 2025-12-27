package com.ucoruh.password;

import java.io.PrintStream;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Collectors;

/**
 * @brief Main class for the Password Manager application.
 *
 * Manages secure storage and retrieval of credentials using a master password.
 * Includes advanced data structures: Sparse Matrix for access pattern tracking.
 */
public class PasswordManager {
  /**
   * @brief Stores the association between account names and their corresponding passwords.
   *
   * This final map holds the credentials for different accounts and is used to manage password data.
   */
  private final Map<String, String> credentials;

  /**
   * @brief The master password used for authentication.
   *
   * This final field stores the master password that is utilized for user authentication and securing the credentials.
   */
  private final String masterPassword;

  /**
   * @brief The storage implementation for passwords.
   */
  private final InterfacePasswordStorage storage;

  /**
   * @brief Access pattern tracking using sparse matrix.
   */
  private final AccessMatrix accessMatrix;

  /**
   * @brief Constructor initializing the manager with a master password.
   *
   * Initializes the credentials map and loads stored credentials.
   *
   * @param masterPassword Master password used for encryption/decryption.
   */
  public PasswordManager(String masterPassword) {
    this.masterPassword = masterPassword;
    this.credentials = new HashMap<>();
    this.storage = PasswordStorageFactory.create(StorageType.FILE, masterPassword);
    this.accessMatrix = new AccessMatrix();
    loadCredentials();
  }

  /**
   * @brief Constructor with specified storage type.
   *
   * @param masterPassword Master password used for encryption/decryption.
   * @param storageType The type of storage to use.
   */
  public PasswordManager(String masterPassword, StorageType storageType) {
    this.masterPassword = masterPassword;
    this.credentials = new HashMap<>();
    this.storage = PasswordStorageFactory.create(storageType, masterPassword);
    this.accessMatrix = new AccessMatrix();
    loadCredentials();
  }

  /**
   * @brief Loads credentials from storage.
   */
  private void loadCredentials() {
    List<Password> passwordList = storage.readAll();
    credentials.clear();

    for (Password p : passwordList) {
      credentials.put(p.getService(), p.getPassword());
    }
  }

  /**
   * @brief Adds a new credential.
   *
   * Inserts the credential for the given account into the internal storage and saves it.
   *
   * @param account Account name.
   * @param password Password for the account.
   */
  public void addCredential(String account, String password) {
    credentials.put(account, password);
    // Create a password list and save it
    List<Password> passwordList = storage.readAll();
    boolean updated = false;

    // Check if the account already exists
    for (Password p : passwordList) {
      if (p.getService().equalsIgnoreCase(account)) {
        p.setPassword(password);
        updated = true;
        break;
      }
    }

    // If not found, add new entry
    if (!updated) {
      passwordList.add(new Password(account, "default_user", password));
    }

    storage.writeAll(passwordList);
  }

  /**
   * @brief Retrieves a credential.
   *
   * Fetches the password associated with the specified account.
   *
   * @param account Account name.
   * @return Password if account exists; otherwise, returns null.
   */
  public String getCredential(String account) {
    // Reload credentials to ensure we have the latest
    loadCredentials();
    // Record access in matrix
    recordServiceAccess(account);
    return credentials.get(account);
  }

  /**
   * @brief Records a service access in the access matrix.
   *
   * @param service Service name
   */
  private void recordServiceAccess(String service) {
    int hour = LocalDateTime.now().getHour();
    accessMatrix.recordAccess(service, hour);
  }

  /**
   * @brief Gets access pattern for a specific service.
   *
   * @param service Service name
   * @return Map of hour to access count
   */
  public Map<Integer, Integer> getAccessPattern(String service) {
    return accessMatrix.getAccessPattern(service);
  }

  /**
   * @brief Gets the most accessed services.
   *
   * @param topN Number of top services to return
   * @return List of service names sorted by access count
   */
  public List<String> getMostAccessedServices(int topN) {
    return accessMatrix.getMostAccessedServices(topN);
  }

  /**
   * @brief Gets total access count for a service.
   *
   * @param service Service name
   * @return Total number of accesses
   */
  public int getTotalAccessCount(String service) {
    return accessMatrix.getTotalAccessCount(service);
  }

  /**
   * @brief Displays the interactive menu and processes user input.
   *
   * Uses dependency injection for Scanner and PrintStream to enable unit testing.
   * Provides options to add, retrieve credentials, generate passwords, or exit.
   *
   * @param scanner The Scanner object for reading user input.
   * @param out The PrintStream object for writing output.
   */
  public void menu(Scanner scanner, PrintStream out) {
    boolean back = false;

    while (!back) {
      out.println("\n==== PASSWORD STORAGE MENU ====");
      out.println("1. Add New Password");
      out.println("2. View All Passwords");
      out.println("3. Update Password");
      out.println("4. Delete Password");
      out.println("5. Generate and Save Password");
      out.println("0. Back to Main Menu");
      out.print("Your choice: ");
      String input = scanner.nextLine();

      try {
        int choice = Integer.parseInt(input);

        switch (choice) {
          case 1:
            storage.add(scanner);
            break;

          case 2:
            storage.view();
            break;

          case 3:
            storage.update(scanner);
            break;

          case 4:
            storage.delete(scanner);
            break;

          case 5:
            generateAndSavePassword(scanner, out);
            break;

          case 0:
            back = true;
            break;

          default:
            out.println("Invalid choice.");
            break;
        }

        // Reload credentials after operations
        loadCredentials();
      } catch (NumberFormatException e) {
        out.println("Invalid number.");
      }
    }
  }

  /**
   * @brief Generates a new password and saves it for a service.
   *
   * @param scanner The Scanner object for user input.
   * @param out The PrintStream object for output.
   */
  private void generateAndSavePassword(Scanner scanner, PrintStream out) {
    out.print("Enter service name: ");
    String service = scanner.nextLine();
    out.print("Enter username: ");
    String username = scanner.nextLine();
    out.print("Enter desired password length: ");

    try {
      int length = Integer.parseInt(scanner.nextLine());

      if (length <= 0) {
        out.println("Password length must be greater than 0.");
        return;
      }

      String password = PasswordGenerator.generatePassword(length);
      out.println("Generated Password: " + password);
      List<Password> passwords = storage.readAll();
      boolean updated = false;

      // Check if service already exists
      for (Password p : passwords) {
        if (p.getService().equalsIgnoreCase(service)) {
          p.setUsername(username);
          p.setPassword(password);
          updated = true;
          break;
        }
      }

      // If not found, add new entry
      if (!updated) {
        passwords.add(new Password(service, username, password));
      }

      storage.writeAll(passwords);
      credentials.put(service, password);
      out.println("Password saved successfully.");
    } catch (NumberFormatException e) {
      out.println("Invalid number.");
    }
  }

  /**
   * @brief Runs the application using the provided Scanner and PrintStream.
   *
   * Initiates the application by requesting the master password and
   * then invoking the interactive menu.
   *
   * @param scanner Scanner for user input.
   * @param out PrintStream for output.
   */
  public static void runApp(Scanner scanner, PrintStream out) {
    out.print("Enter master password: ");
    String masterPwd = scanner.nextLine();
    PasswordManager pm = new PasswordManager(masterPwd);
    pm.menu(scanner, out);
  }

  /**
   * @brief Main method to launch the console application.
   *
   * Entry point of the application. Initializes input and output streams,
   * then invokes the runApp method.
   *
   * @param args Command-line arguments.
   */
  public static void main(String[] args) {
    Scanner scanner = new Scanner(System.in);
    runApp(scanner, System.out);
    scanner.close();
  }

  // ========== INNER CLASSES - DATA STRUCTURES ==========

  /**
   * @brief Sparse Matrix implementation for tracking service access patterns.
   *
   * Uses a HashMap-based approach where only non-zero entries are stored.
   * Matrix dimensions: Service (rows) × Hour of Day (columns, 0-23)
   *
   * Time Complexity:
   * - recordAccess: O(1)
   * - getAccessPattern: O(1)
   * - getMostAccessedServices: O(n log n) where n is number of services
   *
   * Space Complexity: O(k) where k is number of non-zero entries
   */
  private static class AccessMatrix {
    /**
     * @brief Nested map: service -> (hour -> access count)
     */
    private final Map<String, Map<Integer, Integer>> matrix;

    /**
     * @brief Constructor initializes empty matrix.
     */
    public AccessMatrix() {
      this.matrix = new HashMap<>();
    }

    /**
     * @brief Records an access to a service at a specific hour.
     *
     * @param service Service name
     * @param hour Hour of day (0-23)
     */
    public void recordAccess(String service, int hour) {
      if (service == null || hour < 0 || hour > 23) {
        return; // Validate input
      }

      matrix.putIfAbsent(service, new HashMap<>());
      Map<Integer, Integer> hourMap = matrix.get(service);
      hourMap.put(hour, hourMap.getOrDefault(hour, 0) + 1);
    }

    /**
     * @brief Gets access pattern for a specific service.
     *
     * @param service Service name
     * @return Map of hour to access count (empty if service not found)
     */
    public Map<Integer, Integer> getAccessPattern(String service) {
      return matrix.getOrDefault(service, Collections.emptyMap());
    }

    /**
     * @brief Gets total access count for a service across all hours.
     *
     * @param service Service name
     * @return Total access count
     */
    public int getTotalAccessCount(String service) {
      Map<Integer, Integer> pattern = matrix.get(service);

      if (pattern == null) {
        return 0;
      }

      return pattern.values().stream().mapToInt(Integer::intValue).sum();
    }

    /**
     * @brief Gets the most accessed services sorted by total access count.
     *
     * @param topN Number of top services to return
     * @return List of service names sorted by access count (descending)
     */
    public List<String> getMostAccessedServices(int topN) {
      if (topN <= 0) {
        return Collections.emptyList();
      }

      // Create list of (service, totalCount) pairs
      List<Map.Entry<String, Integer>> serviceAccessList = new ArrayList<>();

      for (String service : matrix.keySet()) {
        int totalCount = getTotalAccessCount(service);
        serviceAccessList.add(Map.entry(service, totalCount));
      }

      // Sort by count descending
      serviceAccessList.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
      // Return top N service names
      return serviceAccessList.stream()
             .limit(topN)
             .map(Map.Entry::getKey)
             .collect(Collectors.toList());
    }

    /**
     * @brief Gets all services tracked in the matrix.
     *
     * @return List of service names
     */
    public List<String> getAllServices() {
      return new ArrayList<>(matrix.keySet());
    }

    /**
     * @brief Clears all access data.
     */
    public void clear() {
      matrix.clear();
    }

    /**
     * @brief Gets the number of services tracked.
     *
     * @return Number of services
     */
    public int size() {
      return matrix.size();
    }
  }
}
