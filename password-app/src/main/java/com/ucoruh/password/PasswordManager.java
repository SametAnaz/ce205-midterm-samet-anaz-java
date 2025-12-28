package com.ucoruh.password;

import java.io.PrintStream;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Scanner;
import java.util.Set;
import java.util.Stack;
import java.util.stream.Collectors;

/**
 * @file PasswordManager.java
 * @class PasswordManager
 * @brief Main class for the Password Manager application.
 * @author Password Manager Team
 * @version 1.0
 *
 * Manages secure storage and retrieval of credentials using a master password.
 * Includes advanced data structures: Sparse Matrix for access pattern tracking.
 */
public class PasswordManager {
  /**
   * @brief Stores the association between account names and their corresponding passwords.
   *
   * Uses custom hash table implementation with chaining collision resolution.
   */
  private final CustomHashTable<String, String> credentials;

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
   * @brief Undo stack for command pattern.
   */
  private final CommandStack undoStack;

  /**
   * @brief Service dependency graph.
   */
  private final ServiceGraph serviceGraph;

  /**
   * @brief Redo stack for command pattern.
   */
  private final CommandStack redoStack;

  /**
   * @brief Pending operations queue.
   */
  private final PendingOperationsQueue operationsQueue;

  /**
   * @brief Constructor initializing the manager with a master password.
   *
   * Initializes the credentials map and loads stored credentials.
   *
   * @param masterPassword Master password used for encryption/decryption.
   */
  public PasswordManager(String masterPassword) {
    this.masterPassword = masterPassword;
    this.credentials = new CustomHashTable<>();
    this.storage = PasswordStorageFactory.create(StorageType.FILE, masterPassword);
    this.accessMatrix = new AccessMatrix();
    this.undoStack = new CommandStack();
    this.redoStack = new CommandStack();
    this.serviceGraph = new ServiceGraph();
    this.operationsQueue = new PendingOperationsQueue();
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
    this.credentials = new CustomHashTable<>();
    this.storage = PasswordStorageFactory.create(storageType, masterPassword);
    this.accessMatrix = new AccessMatrix();
    this.undoStack = new CommandStack();
    this.redoStack = new CommandStack();
    this.serviceGraph = new ServiceGraph();
    this.operationsQueue = new PendingOperationsQueue();
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
    // Get old password for undo
    String oldPassword = credentials.get(account);
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

    // Add command to undo stack
    if (oldPassword == null) {
      // New credential - undo should delete it
      undoStack.push(new AddCredentialCommand(account, password));
    } else {
      // Update credential - undo should restore old password
      undoStack.push(new UpdateCredentialCommand(account, oldPassword, password));
    }

    // Clear redo stack on new action
    redoStack.clear();
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

  // ========== UNDO/REDO OPERATIONS ==========

  /**
   * @brief Undoes the last operation.
   *
   * @return true if undo was successful, false if nothing to undo
   */
  public boolean undo() {
    if (undoStack.isEmpty()) {
      return false;
    }

    Command cmd = undoStack.pop();
    cmd.undo();
    redoStack.push(cmd);
    return true;
  }

  /**
   * @brief Redoes the last undone operation.
   *
   * @return true if redo was successful, false if nothing to redo
   */
  public boolean redo() {
    if (redoStack.isEmpty()) {
      return false;
    }

    Command cmd = redoStack.pop();
    cmd.execute();
    undoStack.push(cmd);
    return true;
  }

  /**
   * @brief Checks if undo is available.
   *
   * @return true if there are operations to undo
   */
  public boolean canUndo() {
    return !undoStack.isEmpty();
  }

  /**
   * @brief Checks if redo is available.
   *
   * @return true if there are operations to redo
   */
  public boolean canRedo() {
    return !redoStack.isEmpty();
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

  // ========== CUSTOM HASH TABLE ==========

  /**
   * @brief Custom Hash Table implementation with chaining collision resolution.
   *
   * This implementation uses separate chaining to handle collisions.
   * Provides O(1) average case for put, get, and remove operations.
   *
   * Time Complexity:
   * - put: O(1) average, O(n) worst case
   * - get: O(1) average, O(n) worst case
   * - remove: O(1) average, O(n) worst case
   * - resize: O(n) where n is number of entries
   *
   * Space Complexity: O(n) where n is number of entries
   *
   * @param <K> Key type
   * @param <V> Value type
   */
  private static class CustomHashTable<K, V> {
    /**
     * @brief Entry node for hash table bucket.
     */
    private static class Entry<K, V> {
      /** @brief The key of this entry */
      final K key;
      /** @brief The value associated with the key */
      V value;
      /** @brief Reference to the next entry in the chain */
      Entry<K, V> next;

      /**
       * @brief Constructs an entry with given key and value.
       * @param key The key
       * @param value The value
       */
      Entry(K key, V value) {
        this.key = key;
        this.value = value;
        this.next = null;
      }
    }

    /** @brief Array of buckets for the hash table */
    private Entry<K, V>[] buckets;
    /** @brief Current number of entries in the hash table */
    private int size;
    /** @brief Current capacity of the hash table */
    private int capacity;
    /** @brief Default initial capacity */
    private static final int DEFAULT_CAPACITY = 16;
    /** @brief Load factor threshold for resizing */
    private static final double LOAD_FACTOR_THRESHOLD = 0.75;
    /** @brief Count of collisions that have occurred */
    private int collisionCount;

    /**
     * @brief Constructor initializes hash table with default capacity.
     */
    @SuppressWarnings("unchecked")
    public CustomHashTable() {
      this.capacity = DEFAULT_CAPACITY;
      this.buckets = new Entry[capacity];
      this.size = 0;
      this.collisionCount = 0;
    }

    /**
     * @brief Constructor with specified initial capacity.
     *
     * @param initialCapacity Initial capacity
     */
    @SuppressWarnings("unchecked")
    public CustomHashTable(int initialCapacity) {
      this.capacity = initialCapacity;
      this.buckets = new Entry[capacity];
      this.size = 0;
      this.collisionCount = 0;
    }

    /**
     * @brief Computes hash for a key.
     *
     * @param key Key to hash
     * @return Hash value
     */
    private int hash(K key) {
      if (key == null) {
        return 0;
      }

      return Math.abs(key.hashCode() % capacity);
    }

    /**
     * @brief Inserts or updates a key-value pair.
     *
     * @param key Key
     * @param value Value
     * @return Previous value if key existed, null otherwise
     */
    public V put(K key, V value) {
      if (key == null) {
        throw new IllegalArgumentException("Key cannot be null");
      }

      // Check if resize is needed
      if (getLoadFactor() >= LOAD_FACTOR_THRESHOLD) {
        resize();
      }

      int index = hash(key);
      Entry<K, V> entry = buckets[index];

      // Check if key already exists
      while (entry != null) {
        if (entry.key.equals(key)) {
          V oldValue = entry.value;
          entry.value = value;
          return oldValue;
        }

        entry = entry.next;
      }

      // Add new entry at the beginning of the chain
      Entry<K, V> newEntry = new Entry<>(key, value);
      newEntry.next = buckets[index];

      // Track collision
      if (buckets[index] != null) {
        collisionCount++;
      }

      buckets[index] = newEntry;
      size++;
      return null;
    }

    /**
     * @brief Retrieves value for a key.
     *
     * @param key Key to look up
     * @return Value if found, null otherwise
     */
    public V get(K key) {
      if (key == null) {
        return null;
      }

      int index = hash(key);
      Entry<K, V> entry = buckets[index];

      while (entry != null) {
        if (entry.key.equals(key)) {
          return entry.value;
        }

        entry = entry.next;
      }

      return null;
    }

    /**
     * @brief Removes a key-value pair.
     *
     * @param key Key to remove
     * @return Value if key existed, null otherwise
     */
    public V remove(K key) {
      if (key == null) {
        return null;
      }

      int index = hash(key);
      Entry<K, V> entry = buckets[index];
      Entry<K, V> prev = null;

      while (entry != null) {
        if (entry.key.equals(key)) {
          if (prev == null) {
            buckets[index] = entry.next;
          } else {
            prev.next = entry.next;
          }

          size--;
          return entry.value;
        }

        prev = entry;
        entry = entry.next;
      }

      return null;
    }

    /**
     * @brief Checks if key exists.
     *
     * @param key Key to check
     * @return true if key exists
     */
    public boolean containsKey(K key) {
      return get(key) != null;
    }

    /**
     * @brief Returns number of entries.
     *
     * @return Size
     */
    public int size() {
      return size;
    }

    /**
     * @brief Checks if hash table is empty.
     *
     * @return true if empty
     */
    public boolean isEmpty() {
      return size == 0;
    }

    /**
     * @brief Clears all entries.
     */
    @SuppressWarnings("unchecked")
    public void clear() {
      buckets = new Entry[capacity];
      size = 0;
      collisionCount = 0;
    }

    /**
     * @brief Gets current load factor.
     *
     * @return Load factor
     */
    public double getLoadFactor() {
      return (double) size / capacity;
    }

    /**
     * @brief Gets total collision count.
     *
     * @return Collision count
     */
    public int getCollisionCount() {
      return collisionCount;
    }

    /**
     * @brief Gets all keys.
     *
     * @return List of keys
     */
    public List<K> keySet() {
      List<K> keys = new ArrayList<>();

      for (Entry<K, V> bucket : buckets) {
        Entry<K, V> entry = bucket;

        while (entry != null) {
          keys.add(entry.key);
          entry = entry.next;
        }
      }

      return keys;
    }

    /**
     * @brief Gets all values.
     *
     * @return List of values
     */
    public List<V> values() {
      List<V> vals = new ArrayList<>();

      for (Entry<K, V> bucket : buckets) {
        Entry<K, V> entry = bucket;

        while (entry != null) {
          vals.add(entry.value);
          entry = entry.next;
        }
      }

      return vals;
    }

    /**
     * @brief Resizes the hash table when load factor exceeds threshold.
     */
    @SuppressWarnings("unchecked")
    private void resize() {
      int newCapacity = capacity * 2;
      Entry<K, V>[] oldBuckets = buckets;
      buckets = new Entry[newCapacity];
      capacity = newCapacity;
      size = 0;
      collisionCount = 0;

      // Rehash all entries
      for (Entry<K, V> bucket : oldBuckets) {
        Entry<K, V> entry = bucket;

        while (entry != null) {
          put(entry.key, entry.value);
          entry = entry.next;
        }
      }
    }
  }

  // ========== HEAP SORT IMPLEMENTATION ==========

  /**
   * @brief Service usage data for sorting.
   */
  private static class ServiceUsage implements Comparable<ServiceUsage> {
    /** @brief The service name */
    private final String service;
    /** @brief The usage count for this service */
    private final int usageCount;

    /**
     * @brief Constructs a ServiceUsage object.
     * @param service The service name
     * @param usageCount The usage count
     */
    public ServiceUsage(String service, int usageCount) {
      this.service = service;
      this.usageCount = usageCount;
    }

    /**
     * @brief Gets the service name.
     * @return The service name
     */
    public String getService() {
      return service;
    }

    /**
     * @brief Gets the usage count.
     * @return The usage count
     */
    public int getUsageCount() {
      return usageCount;
    }

    @Override
    public int compareTo(ServiceUsage other) {
      // Natural order: ascending by usage count
      return Integer.compare(this.usageCount, other.usageCount);
    }
  }

  /**
   * @brief Sorts service usage data using heap sort algorithm.
   *
   * Time Complexity: O(n log n)
   * Space Complexity: O(1) - in-place sorting
   *
   * @param arr Array to sort
   */
  private void heapSort(ServiceUsage[] arr) {
    int n = arr.length;

    // Build max heap
    for (int i = n / 2 - 1; i >= 0; i--) {
      heapify(arr, n, i);
    }

    // Extract elements from heap one by one
    for (int i = n - 1; i > 0; i--) {
      // Move current root to end
      ServiceUsage temp = arr[0];
      arr[0] = arr[i];
      arr[i] = temp;
      // Heapify the reduced heap
      heapify(arr, i, 0);
    }
  }

  /**
   * @brief Maintains heap property for a subtree.
   *
   * @param arr Array representing heap
   * @param n Size of heap
   * @param i Root index of subtree
   */
  private void heapify(ServiceUsage[] arr, int n, int i) {
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    // Check if left child is larger than root
    if (left < n && arr[left].compareTo(arr[largest]) > 0) {
      largest = left;
    }

    // Check if right child is larger than current largest
    if (right < n && arr[right].compareTo(arr[largest]) > 0) {
      largest = right;
    }

    // If largest is not root
    if (largest != i) {
      ServiceUsage swap = arr[i];
      arr[i] = arr[largest];
      arr[largest] = swap;
      // Recursively heapify the affected subtree
      heapify(arr, n, largest);
    }
  }

  /**
   * @brief Gets most used services sorted by usage count using heap sort.
   *
   * Combines access matrix data with heap sort for efficient ranking.
   *
   * @return List of services sorted by usage count
   */
  public List<String> getMostUsedServicesByHeapSort() {
    List<String> services = accessMatrix.getAllServices();

    if (services.isEmpty()) {
      return new ArrayList<>();
    }

    // Create array of service usage
    ServiceUsage[] usageArray = new ServiceUsage[services.size()];

    for (int i = 0; i < services.size(); i++) {
      String service = services.get(i);
      int count = accessMatrix.getTotalAccessCount(service);
      usageArray[i] = new ServiceUsage(service, count);
    }

    // Sort using heap sort (ascending)
    heapSort(usageArray);
    // Reverse to get descending order (most used first)
    List<String> result = new ArrayList<>();

    for (int i = usageArray.length - 1; i >= 0; i--) {
      ServiceUsage usage = usageArray[i];
      result.add(usage.getService() + " (" + usage.getUsageCount() + " accesses)");
    }

    return result;
  }

  // ========== COMMAND PATTERN FOR UNDO/REDO ==========

  /**
   * @brief Command interface for undo/redo operations.
   */
  private interface Command {
    void execute();
    void undo();
  }

  /**
   * @brief Command for adding a new credential.
   */
  private class AddCredentialCommand implements Command {
    private final String account;
    private final String password;

    AddCredentialCommand(String account, String password) {
      this.account = account;
      this.password = password;
    }

    @Override
    public void execute() {
      credentials.put(account, password);
      List<Password> passwordList = storage.readAll();
      passwordList.add(new Password(account, "default_user", password));
      storage.writeAll(passwordList);
    }

    @Override
    public void undo() {
      credentials.remove(account);
      List<Password> passwordList = storage.readAll();
      passwordList.removeIf(p -> p.getService().equalsIgnoreCase(account));
      storage.writeAll(passwordList);
    }
  }

  /**
   * @brief Command for updating an existing credential.
   */
  private class UpdateCredentialCommand implements Command {
    private final String account;
    private final String oldPassword;
    private final String newPassword;

    UpdateCredentialCommand(String account, String oldPassword, String newPassword) {
      this.account = account;
      this.oldPassword = oldPassword;
      this.newPassword = newPassword;
    }

    @Override
    public void execute() {
      credentials.put(account, newPassword);
      List<Password> passwordList = storage.readAll();

      for (Password p : passwordList) {
        if (p.getService().equalsIgnoreCase(account)) {
          p.setPassword(newPassword);
          break;
        }
      }

      storage.writeAll(passwordList);
    }

    @Override
    public void undo() {
      credentials.put(account, oldPassword);
      List<Password> passwordList = storage.readAll();

      for (Password p : passwordList) {
        if (p.getService().equalsIgnoreCase(account)) {
          p.setPassword(oldPassword);
          break;
        }
      }

      storage.writeAll(passwordList);
    }
  }

  /**
   * @brief Stack implementation for command history.
   *
   * Uses linked list approach for O(1) push/pop operations.
   *
   * Time Complexity:
   * - push: O(1)
   * - pop: O(1)
   * - peek: O(1)
   * - isEmpty: O(1)
   *
   * Space Complexity: O(n) where n is number of commands
   */
  private static class CommandStack {
    /**
     * @brief Node for stack implementation.
     */
    private static class Node {
      /** @brief The command stored in this node */
      Command command;
      /** @brief Reference to the next node */
      Node next;

      /**
       * @brief Constructs a node with the given command.
       * @param command The command to store
       */
      Node(Command command) {
        this.command = command;
        this.next = null;
      }
    }

    /** @brief Reference to the top of the stack */
    private Node top;
    /** @brief Current number of elements in the stack */
    private int size;

    /**
     * @brief Constructor initializes empty stack.
     */
    public CommandStack() {
      this.top = null;
      this.size = 0;
    }

    /**
     * @brief Pushes a command onto the stack.
     *
     * @param command Command to push
     */
    public void push(Command command) {
      Node newNode = new Node(command);
      newNode.next = top;
      top = newNode;
      size++;
    }

    /**
     * @brief Pops a command from the stack.
     *
     * @return Command from top of stack, or null if empty
     */
    public Command pop() {
      if (isEmpty()) {
        return null;
      }

      Command command = top.command;
      top = top.next;
      size--;
      return command;
    }

    /**
     * @brief Peeks at the top command without removing it.
     *
     * @return Command from top of stack, or null if empty
     */
    public Command peek() {
      return isEmpty() ? null : top.command;
    }

    /**
     * @brief Checks if stack is empty.
     *
     * @return true if stack has no elements
     */
    public boolean isEmpty() {
      return top == null;
    }

    /**
     * @brief Gets the size of the stack.
     *
     * @return Number of commands in stack
     */
    public int size() {
      return size;
    }

    /**
     * @brief Clears all commands from the stack.
     */
    public void clear() {
      top = null;
      size = 0;
    }
  }

  // ========== SERVICE DEPENDENCY GRAPH (BFS, DFS, SCC) ==========

  /**
   * @brief Graph data structure for tracking service dependencies.
   * @details Implements directed graph with BFS, DFS, and Strongly Connected Components (Kosaraju's algorithm).
   *
   * Time Complexity:
   * - addEdge: O(1)
   * - BFS: O(V + E)
   * - DFS: O(V + E)
   * - SCC: O(V + E)
   *
   * Space Complexity: O(V + E)
   */
  public static class ServiceGraph {
    private final Map<String, List<String>> adjacencyList;
    private final Map<String, List<String>> reverseAdjacencyList;

    /**
     * @brief Constructor initializes empty graph.
     */
    public ServiceGraph() {
      this.adjacencyList = new HashMap<>();
      this.reverseAdjacencyList = new HashMap<>();
    }

    /**
     * @brief Adds a directed edge from service1 to service2.
     * @details Represents that service1 depends on service2.
     *
     * @param service1 Source service
     * @param service2 Destination service
     */
    public void addEdge(String service1, String service2) {
      adjacencyList.putIfAbsent(service1, new ArrayList<>());
      adjacencyList.putIfAbsent(service2, new ArrayList<>());
      adjacencyList.get(service1).add(service2);
      // Build reverse graph for SCC
      reverseAdjacencyList.putIfAbsent(service1, new ArrayList<>());
      reverseAdjacencyList.putIfAbsent(service2, new ArrayList<>());
      reverseAdjacencyList.get(service2).add(service1);
    }

    /**
     * @brief Breadth-First Search traversal starting from a service.
     * @details Returns list of services reachable from start in BFS order.
     *
     * Time Complexity: O(V + E)
     * Space Complexity: O(V)
     *
     * @param start Starting service
     * @return List of services in BFS order
     */
    public List<String> bfs(String start) {
      if (!adjacencyList.containsKey(start)) {
        return new ArrayList<>();
      }

      List<String> result = new ArrayList<>();
      Set<String> visited = new HashSet<>();
      Queue<String> queue = new LinkedList<>();
      queue.offer(start);
      visited.add(start);

      while (!queue.isEmpty()) {
        String current = queue.poll();
        result.add(current);
        List<String> neighbors = adjacencyList.get(current);

        if (neighbors != null) {
          for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
              visited.add(neighbor);
              queue.offer(neighbor);
            }
          }
        }
      }

      return result;
    }

    /**
     * @brief Depth-First Search traversal starting from a service.
     * @details Returns list of services reachable from start in DFS order.
     *
     * Time Complexity: O(V + E)
     * Space Complexity: O(V)
     *
     * @param start Starting service
     * @return List of services in DFS order
     */
    public List<String> dfs(String start) {
      if (!adjacencyList.containsKey(start)) {
        return new ArrayList<>();
      }

      List<String> result = new ArrayList<>();
      Set<String> visited = new HashSet<>();
      dfsHelper(start, visited, result);
      return result;
    }

    /**
     * @brief Helper method for DFS traversal.
     *
     * @param current Current service being visited
     * @param visited Set of visited services
     * @param result List to store DFS order
     */
    private void dfsHelper(String current, Set<String> visited, List<String> result) {
      visited.add(current);
      result.add(current);
      List<String> neighbors = adjacencyList.get(current);

      if (neighbors != null) {
        for (String neighbor : neighbors) {
          if (!visited.contains(neighbor)) {
            dfsHelper(neighbor, visited, result);
          }
        }
      }
    }

    /**
     * @brief Finds all Strongly Connected Components using Kosaraju's algorithm.
     * @details A SCC is a maximal set of vertices where each vertex is reachable from every other.
     *
     * Algorithm:
     * 1. Perform DFS on original graph to get finish times
     * 2. Perform DFS on reversed graph in decreasing finish time order
     * 3. Each DFS tree in step 2 is a SCC
     *
     * Time Complexity: O(V + E)
     * Space Complexity: O(V)
     *
     * @return List of SCCs, each SCC is a list of services
     */
    public List<List<String>> findStronglyConnectedComponents() {
      List<List<String>> sccs = new ArrayList<>();
      // Step 1: Get finish times using DFS
      Stack<String> finishStack = new Stack<>();
      Set<String> visited = new HashSet<>();

      for (String service : adjacencyList.keySet()) {
        if (!visited.contains(service)) {
          fillFinishStack(service, visited, finishStack);
        }
      }

      // Step 2: Process vertices in decreasing finish time order on reversed graph
      visited.clear();

      while (!finishStack.isEmpty()) {
        String service = finishStack.pop();

        if (!visited.contains(service)) {
          List<String> scc = new ArrayList<>();
          dfsReverse(service, visited, scc);
          sccs.add(scc);
        }
      }

      return sccs;
    }

    /**
     * @brief Fills stack with services in order of finish time.
     *
     * @param current Current service
     * @param visited Set of visited services
     * @param finishStack Stack to store finish order
     */
    private void fillFinishStack(String current, Set<String> visited, Stack<String> finishStack) {
      visited.add(current);
      List<String> neighbors = adjacencyList.get(current);

      if (neighbors != null) {
        for (String neighbor : neighbors) {
          if (!visited.contains(neighbor)) {
            fillFinishStack(neighbor, visited, finishStack);
          }
        }
      }

      finishStack.push(current);
    }

    /**
     * @brief DFS on reversed graph to find a SCC.
     *
     * @param current Current service
     * @param visited Set of visited services
     * @param scc List to store current SCC
     */
    private void dfsReverse(String current, Set<String> visited, List<String> scc) {
      visited.add(current);
      scc.add(current);
      List<String> neighbors = reverseAdjacencyList.get(current);

      if (neighbors != null) {
        for (String neighbor : neighbors) {
          if (!visited.contains(neighbor)) {
            dfsReverse(neighbor, visited, scc);
          }
        }
      }
    }

    /**
     * @brief Gets all services in the graph.
     *
     * @return Set of all service names
     */
    public Set<String> getAllServices() {
      return new HashSet<>(adjacencyList.keySet());
    }

    /**
     * @brief Gets neighbors of a service.
     *
     * @param service Service name
     * @return List of neighboring services
     */
    public List<String> getNeighbors(String service) {
      List<String> neighbors = adjacencyList.get(service);
      return neighbors != null ? new ArrayList<>(neighbors) : new ArrayList<>();
    }

    /**
     * @brief Checks if graph contains a service.
     *
     * @param service Service name
     * @return true if service exists in graph
     */
    public boolean containsService(String service) {
      return adjacencyList.containsKey(service);
    }

    /**
     * @brief Clears the graph.
     */
    public void clear() {
      adjacencyList.clear();
      reverseAdjacencyList.clear();
    }
  }

  /**
   * @brief Analyzes service dependencies and returns related services.
   * @details Uses BFS to find all services reachable from the given service.
   *
   * @param service Service name
   * @return List of related services
   */
  public List<String> getRelatedServices(String service) {
    return serviceGraph.bfs(service);
  }

  /**
   * @brief Adds a dependency relationship between two services.
   *
   * @param service1 Source service
   * @param service2 Dependent service
   */
  public void addServiceDependency(String service1, String service2) {
    serviceGraph.addEdge(service1, service2);
  }

  /**
   * @brief Gets all strongly connected components in service dependencies.
   *
   * @return List of SCCs
   */
  public List<List<String>> getServiceClusters() {
    return serviceGraph.findStronglyConnectedComponents();
  }

  /**
   * @brief Gets the service dependency graph.
   *
   * @return ServiceGraph instance
   */
  public ServiceGraph getServiceGraph() {
    return serviceGraph;
  }

  /**
   * @brief Queues a pending operation.
   *
   * @param operation Operation description
   */
  public void queueOperation(String operation) {
    operationsQueue.enqueue(operation);
  }

  /**
   * @brief Processes all pending operations.
   *
   * @return List of processed operations
   */
  public List<String> processPendingOperations() {
    List<String> processed = new ArrayList<>();

    while (!operationsQueue.isEmpty()) {
      processed.add(operationsQueue.dequeue());
    }

    return processed;
  }

  /**
   * @brief Gets the count of pending operations.
   *
   * @return Number of pending operations
   */
  public int getPendingOperationsCount() {
    return operationsQueue.size();
  }

  /**
   * @brief Peeks at the next pending operation without removing it.
   *
   * @return Next operation or null if queue is empty
   */
  public String peekNextOperation() {
    return operationsQueue.peek();
  }

  /**
   * @brief Gets the pending operations queue.
   *
   * @return PendingOperationsQueue instance
   */
  public PendingOperationsQueue getOperationsQueue() {
    return operationsQueue;
  }

  /**
   * @brief Custom Queue implementation using linked nodes.
   *
   * Implements FIFO (First-In-First-Out) data structure for pending operations.
   */
  public static class PendingOperationsQueue {
    /**
     * @brief Node class for queue elements.
     */
    private static class Node {
      /** @brief The operation stored in this node */
      String operation;
      /** @brief Reference to the next node */
      Node next;

      /**
       * @brief Constructs a node with the given operation.
       * @param operation The operation to store
       */
      Node(String operation) {
        this.operation = operation;
        this.next = null;
      }
    }

    /** @brief Front of queue (dequeue from here) */
    private Node front;
    /** @brief Rear of queue (enqueue to here) */
    private Node rear;
    /** @brief Current number of elements in the queue */
    private int size;

    /**
     * @brief Constructor initializing empty queue.
     */
    public PendingOperationsQueue() {
      this.front = null;
      this.rear = null;
      this.size = 0;
    }

    /**
     * @brief Adds an operation to the rear of the queue.
     *
     * Time complexity: O(1)
     *
     * @param operation Operation to enqueue
     */
    public void enqueue(String operation) {
      Node newNode = new Node(operation);

      if (isEmpty()) {
        front = newNode;
        rear = newNode;
      } else {
        rear.next = newNode;
        rear = newNode;
      }

      size++;
    }

    /**
     * @brief Removes and returns the operation from the front of the queue.
     *
     * Time complexity: O(1)
     *
     * @return Front operation, or null if queue is empty
     */
    public String dequeue() {
      if (isEmpty()) {
        return null;
      }

      String operation = front.operation;
      front = front.next;

      if (front == null) {
        rear = null;  // Queue is now empty
      }

      size--;
      return operation;
    }

    /**
     * @brief Returns the operation at the front without removing it.
     *
     * Time complexity: O(1)
     *
     * @return Front operation, or null if queue is empty
     */
    public String peek() {
      if (isEmpty()) {
        return null;
      }

      return front.operation;
    }

    /**
     * @brief Checks if the queue is empty.
     *
     * Time complexity: O(1)
     *
     * @return true if queue is empty, false otherwise
     */
    public boolean isEmpty() {
      return size == 0;
    }

    /**
     * @brief Gets the current size of the queue.
     *
     * Time complexity: O(1)
     *
     * @return Number of operations in the queue
     */
    public int size() {
      return size;
    }

    /**
     * @brief Clears all operations from the queue.
     *
     * Time complexity: O(1)
     */
    public void clear() {
      front = null;
      rear = null;
      size = 0;
    }

    /**
     * @brief Gets all operations as a list without removing them.
     *
     * Time complexity: O(n)
     *
     * @return List of all operations in FIFO order
     */
    public List<String> toList() {
      List<String> operations = new ArrayList<>();
      Node current = front;

      while (current != null) {
        operations.add(current.operation);
        current = current.next;
      }

      return operations;
    }
  }
}
