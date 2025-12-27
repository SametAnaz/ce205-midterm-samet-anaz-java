package com.ucoruh.password;

import java.util.ArrayList;
import java.util.List;

/**
 * @file Password.java
 * @class Password
 * @brief Represents a stored password entry for a specific service.
 *
 * This class provides a structure to store and manage credentials such as
 * service name, username, and password. You can retrieve or update these
 * fields through the provided getter and setter methods.
 *
 * Additionally, this class maintains a history of previous passwords using
 * a doubly linked list data structure for efficient insertion and traversal.
 */
public class Password {
  /**
   * @brief The name of the service (e.g., Gmail, Facebook).
   */
  private String service;

  /**
   * @brief The associated username for the service.
   */
  private String username;

  /**
   * @brief The password string for the service.
   */
  private String password;

  /**
   * @brief Password history tracker using doubly linked list.
   */
  private PasswordHistory history;

  /**
   * @brief Constructs a Password object with service, username, and password.
   *
   * @param service the service name (e.g., Gmail, Facebook)
   * @param username the associated username
   * @param password the password string
   */
  public Password(String service, String username, String password) {
    this.service = service;
    this.username = username;
    this.password = password;
    this.history = new PasswordHistory();
    this.history.addPassword(password, System.currentTimeMillis());
  }

  /**
   * @brief Returns the service name.
   *
   * @return the service name associated with this password entry.
   */
  public String getService() {
    return service;
  }

  /**
   * @brief Returns the username.
   *
   * @return the username associated with this password entry.
   */
  public String getUsername() {
    return username;
  }

  /**
   * @brief Returns the password string.
   *
   * @return the password string associated with this password entry.
   */
  public String getPassword() {
    return password;
  }

  /**
   * @brief Sets a new username for this password entry.
   *
   * @param username the new username to be set for this password entry.
   */
  public void setUsername(String username) {
    this.username = username;
  }

  /**
   * @brief Sets a new password for this password entry.
   *
   * @param password the new password string to be set for this password entry.
   */
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   * @brief Sets a new password and records it in history.
   *
   * @param password the new password string
   */
  public void setPasswordWithHistory(String password) {
    this.password = password;
    this.history.addPassword(password, System.currentTimeMillis());
  }

  /**
   * @brief Gets the password history.
   *
   * @return List of previous passwords with timestamps
   */
  public List<PasswordHistoryEntry> getPasswordHistory() {
    return this.history.getHistory();
  }

  /**
   * @brief Gets the number of passwords in history.
   *
   * @return Size of history
   */
  public int getHistorySize() {
    return this.history.getSize();
  }

  /**
   * @brief Clears the password history.
   */
  public void clearHistory() {
    this.history.clear();
  }

  /**
   * @brief Returns a string representation of the Password object.
   *
   * @return a string with service, username, and password details.
   */
  @Override
  public String toString() {
    return "Service: " + service + " | Username: " + username + " | Password: " + password;
  }

  // ========== INNER CLASSES ==========

  /**
   * @brief Represents a single password history entry.
   */
  public static class PasswordHistoryEntry {
    private final String password;
    private final long timestamp;

    /**
     * @brief Constructor for history entry.
     *
     * @param password The password string
     * @param timestamp When the password was set
     */
    public PasswordHistoryEntry(String password, long timestamp) {
      this.password = password;
      this.timestamp = timestamp;
    }

    /**
     * @brief Gets the password.
     *
     * @return The password string
     */
    public String getPassword() {
      return password;
    }

    /**
     * @brief Gets the timestamp.
     *
     * @return The timestamp in milliseconds
     */
    public long getTimestamp() {
      return timestamp;
    }
  }

  /**
   * @brief Inner class implementing doubly linked list for password history tracking.
   *
   * This data structure allows efficient insertion at both ends and bidirectional
   * traversal through the history. Each node stores a password and its timestamp.
   *
   * Time Complexity:
   * - Add: O(1)
   * - Get all: O(n)
   * - Clear: O(1)
   *
   * Space Complexity: O(n) where n is the number of passwords in history.
   */
  private static class PasswordHistory {
    /**
     * @brief Node class for doubly linked list.
     */
    private static class Node {
      String password;
      long timestamp;
      Node prev;
      Node next;

      /**
       * @brief Constructor for Node.
       *
       * @param password The password to store
       * @param timestamp When the password was set
       */
      Node(String password, long timestamp) {
        this.password = password;
        this.timestamp = timestamp;
        this.prev = null;
        this.next = null;
      }
    }

    private Node head;
    private Node tail;
    private int size;

    /**
     * @brief Constructor initializes empty history.
     */
    public PasswordHistory() {
      this.head = null;
      this.tail = null;
      this.size = 0;
    }

    /**
     * @brief Adds a password to the end of the history.
     *
     * Time Complexity: O(1)
     *
     * @param password The password to add
     * @param timestamp When the password was set
     */
    public void addPassword(String password, long timestamp) {
      Node newNode = new Node(password, timestamp);

      if (head == null) {
        // First node
        head = newNode;
        tail = newNode;
      } else {
        // Add to end
        tail.next = newNode;
        newNode.prev = tail;
        tail = newNode;
      }

      size++;
    }

    /**
     * @brief Gets all passwords in history as a list.
     *
     * Time Complexity: O(n) where n is the number of passwords
     *
     * @return List of password history entries
     */
    public List<PasswordHistoryEntry> getHistory() {
      List<PasswordHistoryEntry> result = new ArrayList<>();
      Node current = head;

      while (current != null) {
        result.add(new PasswordHistoryEntry(current.password, current.timestamp));
        current = current.next;
      }

      return result;
    }

    /**
     * @brief Gets the size of the history.
     *
     * @return Number of passwords in history
     */
    public int getSize() {
      return size;
    }

    /**
     * @brief Clears all history.
     *
     * Time Complexity: O(1)
     */
    public void clear() {
      head = null;
      tail = null;
      size = 0;
    }
  }
}
