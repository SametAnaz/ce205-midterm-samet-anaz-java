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
   * @brief Redo stack for command pattern.
   */
  private final CommandStack redoStack;

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
      final K key;
      V value;
      Entry<K, V> next;

      Entry(K key, V value) {
        this.key = key;
        this.value = value;
        this.next = null;
      }
    }

    private Entry<K, V>[] buckets;
    private int size;
    private int capacity;
    private static final int DEFAULT_CAPACITY = 16;
    private static final double LOAD_FACTOR_THRESHOLD = 0.75;
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
    private final String service;
    private final int usageCount;

    public ServiceUsage(String service, int usageCount) {
      this.service = service;
      this.usageCount = usageCount;
    }

    public String getService() {
      return service;
    }

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
      Command command;
      Node next;

      Node(Command command) {
        this.command = command;
        this.next = null;
      }
    }

    private Node top;
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
}
