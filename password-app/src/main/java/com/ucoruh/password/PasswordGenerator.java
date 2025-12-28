package com.ucoruh.password;

import java.util.Random;
import java.util.Scanner;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * @file PasswordGenerator.java
 * @class PasswordGenerator
 * @brief Utility class for generating random passwords.
 * @author Password Manager Team
 * @version 1.0
 * @details This class provides methods to generate secure random passwords using configurable
 * character sets.
 */
public class PasswordGenerator {

  /**
   * @brief Set of uppercase characters used for password generation
   * @param chars A-Z uppercase letters
   */
  private static final String UPPERCASE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  /**
   * @brief Set of lowercase characters used for password generation
   * @param chars a-z lowercase letters
   */
  private static final String LOWERCASE_CHARS = "abcdefghijklmnopqrstuvwxyz";

  /**
   * @brief Set of numeric digits used for password generation
   * @param chars 0-9 digits
   */
  private static final String DIGIT_CHARS = "0123456789";

  /**
   * @brief Set of special characters used for password generation
   * @param chars Special characters including !@#$%^&*()_-+=<>?/[]{}|
   */
  private static final String SPECIAL_CHARS = "!@#$%^&*()_-+=<>?/[]{}|";

  /**
   * @brief Combined set of all characters used for password generation
   * @param chars Combination of uppercase, lowercase, digits, and special characters
   */
  private static final String CHARACTERS = UPPERCASE_CHARS + LOWERCASE_CHARS + DIGIT_CHARS + SPECIAL_CHARS;

  /**
   * @brief Generates a random password of a given length
   * @details This method uses a random number generator and a predefined character set to
   * create a password string of the specified length. If a negative length is provided,
   * an empty string is returned.
   *
   * @param length The desired length of the password
   * @return String A randomly generated password
   */
  public static String generatePassword(int length) {
    // For backward compatibility, use all character sets
    return generatePassword(length, true, true, true, true);
  }

  /**
   * @brief Generates a random password with specific character sets
   * @details This method allows selective inclusion of character sets (uppercase letters,
   * lowercase letters, digits, and special characters) in the generated password.
   * At least one character set must be included.
   *
   * @param length The desired length of the password
   * @param includeUppercase Whether to include uppercase letters (A-Z)
   * @param includeLowercase Whether to include lowercase letters (a-z)
   * @param includeDigits Whether to include digits (0-9)
   * @param includeSpecial Whether to include special characters
   * @return String A randomly generated password meeting the specified criteria
   */
  public static String generatePassword(int length, boolean includeUppercase,
                                        boolean includeLowercase, boolean includeDigits,
                                        boolean includeSpecial) {
    // Return empty string for zero or negative length
    if (length <= 0) {
      return "";
    }

    // Build the character set based on includes
    StringBuilder charSetBuilder = new StringBuilder();

    if (includeUppercase) charSetBuilder.append(UPPERCASE_CHARS);

    if (includeLowercase) charSetBuilder.append(LOWERCASE_CHARS);

    if (includeDigits) charSetBuilder.append(DIGIT_CHARS);

    if (includeSpecial) charSetBuilder.append(SPECIAL_CHARS);

    // If no character set is selected, use lowercase as default
    String charSet = charSetBuilder.length() > 0 ? charSetBuilder.toString() : LOWERCASE_CHARS;
    // Generate the password
    StringBuilder password = new StringBuilder(length);
    Random random = new Random();

    // Ensure at least one character from each selected char set
    if (length >= 1 && includeUppercase && password.length() < length) {
      password.append(UPPERCASE_CHARS.charAt(random.nextInt(UPPERCASE_CHARS.length())));
    }

    if (length >= 2 && includeLowercase && password.length() < length) {
      password.append(LOWERCASE_CHARS.charAt(random.nextInt(LOWERCASE_CHARS.length())));
    }

    if (length >= 3 && includeDigits && password.length() < length) {
      password.append(DIGIT_CHARS.charAt(random.nextInt(DIGIT_CHARS.length())));
    }

    if (length >= 4 && includeSpecial && password.length() < length) {
      password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));
    }

    // Fill the rest with random characters from the selected set
    while (password.length() < length) {
      int index = random.nextInt(charSet.length());
      password.append(charSet.charAt(index));
    }

    // Shuffle the characters to avoid predictable patterns
    char[] passChars = password.toString().toCharArray();

    for (int i = passChars.length - 1; i > 0; i--) {
      int j = random.nextInt(i + 1);
      char temp = passChars[i];
      passChars[i] = passChars[j];
      passChars[j] = temp;
    }

    return new String(passChars);
  }

  /**
   * @brief Prompts user for password length and generates a password
   * @details This method reads the desired password length from the user input using the provided
   * Scanner, then generates and prints the random password.
   *
   * @param scanner Scanner object for reading user input
   */
  public static void generate(Scanner scanner) {
    System.out.print("Enter desired password length: ");

    try {
      int length = Integer.parseInt(scanner.nextLine());
      String newPassword = generatePassword(length);
      System.out.println("Generated Password: " + newPassword);
    } catch (NumberFormatException e) {
      System.out.println("Invalid input. Please enter a valid number.");
    }
  }

  // ========== KMP STRING MATCHING ALGORITHM ==========

  /**
   * @brief Computes the Longest Proper Prefix which is also Suffix (LPS) array.
   * @details This array is used by the KMP algorithm to avoid redundant comparisons.
   *
   * Time Complexity: O(m) where m is pattern length
   * Space Complexity: O(m)
   *
   * @param pattern The pattern string to compute LPS array for
   * @return int[] The LPS array
   */
  private static int[] computeLPSArray(String pattern) {
    int m = pattern.length();
    int[] lps = new int[m];
    int len = 0; // Length of previous longest prefix suffix
    int i = 1;
    lps[0] = 0; // lps[0] is always 0

    while (i < m) {
      if (pattern.charAt(i) == pattern.charAt(len)) {
        len++;
        lps[i] = len;
        i++;
      } else {
        if (len != 0) {
          len = lps[len - 1];
        } else {
          lps[i] = 0;
          i++;
        }
      }
    }

    return lps;
  }

  /**
   * @brief Searches for pattern in text using KMP algorithm.
   * @details KMP (Knuth-Morris-Pratt) algorithm searches for occurrences of a pattern
   * within a text by using the LPS array to skip unnecessary comparisons.
   *
   * Time Complexity: O(n + m) where n is text length, m is pattern length
   * Space Complexity: O(m)
   *
   * @param text The text to search in
   * @param pattern The pattern to search for
   * @return int Index of first occurrence, or -1 if not found
   */
  public static int kmpSearch(String text, String pattern) {
    if (text == null || pattern == null || pattern.isEmpty()) {
      return -1;
    }

    int n = text.length();
    int m = pattern.length();

    if (m > n) {
      return -1;
    }

    int[] lps = computeLPSArray(pattern);
    int i = 0; // Index for text
    int j = 0; // Index for pattern

    while (i < n) {
      if (pattern.charAt(j) == text.charAt(i)) {
        i++;
        j++;
      }

      if (j == m) {
        return i - j; // Pattern found at index i-j
      } else if (i < n && pattern.charAt(j) != text.charAt(i)) {
        if (j != 0) {
          j = lps[j - 1];
        } else {
          i++;
        }
      }
    }

    return -1; // Pattern not found
  }

  /**
   * @brief Checks if a password contains a specific pattern.
   *
   * @param password The password to check
   * @param pattern The pattern to search for
   * @return boolean true if pattern is found, false otherwise
   */
  public static boolean containsPattern(String password, String pattern) {
    return kmpSearch(password, pattern) != -1;
  }

  /**
   * @brief Checks if a password contains weak patterns.
   * @details Common weak patterns include: "123", "abc", "password", "qwerty", etc.
   *
   * @param password The password to check
   * @return boolean true if weak pattern found, false otherwise
   */
  public static boolean isWeakPattern(String password) {
    if (password == null || password.isEmpty()) {
      return true;
    }

    // Common weak patterns
    String[] weakPatterns = {
      "123", "1234", "12345", "123456",
      "abc", "abcd", "abcde",
      "password", "pass", "pwd",
      "qwerty", "admin", "user",
      "000", "111", "aaa",
      "password123", "admin123"
    };
    // Check case-insensitive
    String lowerPassword = password.toLowerCase();

    for (String pattern : weakPatterns) {
      if (containsPattern(lowerPassword, pattern)) {
        return true;
      }
    }

    // Check for sequential numbers (ascending)
    for (int i = 0; i < password.length() - 2; i++) {
      if (Character.isDigit(password.charAt(i)) &&
          Character.isDigit(password.charAt(i + 1)) &&
          Character.isDigit(password.charAt(i + 2))) {
        int d1 = password.charAt(i) - '0';
        int d2 = password.charAt(i + 1) - '0';
        int d3 = password.charAt(i + 2) - '0';

        if (d2 == d1 + 1 && d3 == d2 + 1) {
          return true; // Sequential like 123, 456, 789
        }
      }
    }

    // Check for repeated characters (3 or more)
    for (int i = 0; i < password.length() - 2; i++) {
      if (password.charAt(i) == password.charAt(i + 1) &&
          password.charAt(i) == password.charAt(i + 2)) {
        return true; // Repeated like aaa, 111
      }
    }

    return false;
  }

  /**
   * @brief Generates a strong password that doesn't contain weak patterns.
   * @details Keeps generating passwords until one passes the weak pattern check.
   *
   * @param length Desired password length
   * @return String A strong password
   */
  public static String generateStrongPassword(int length) {
    String password;
    int maxAttempts = 100;
    int attempts = 0;

    do {
      password = generatePassword(length);
      attempts++;
    } while (isWeakPattern(password) && attempts < maxAttempts);

    return password;
  }

  // ========== HUFFMAN CODING FOR PASSWORD COMPRESSION ==========

  /**
   * @brief Huffman Tree Node for encoding/decoding.
   * @details Used in Huffman Coding algorithm for lossless compression.
   */
  public static class HuffmanNode implements Comparable<HuffmanNode> {
    char character;
    int frequency;
    HuffmanNode left;
    HuffmanNode right;

    /**
     * @brief Constructor for leaf nodes (actual characters).
     */
    public HuffmanNode(char character, int frequency) {
      this.character = character;
      this.frequency = frequency;
      this.left = null;
      this.right = null;
    }

    /**
     * @brief Constructor for internal nodes.
     */
    public HuffmanNode(int frequency, HuffmanNode left, HuffmanNode right) {
      this.character = '\0';
      this.frequency = frequency;
      this.left = left;
      this.right = right;
    }

    /**
     * @brief Checks if node is a leaf.
     */
    public boolean isLeaf() {
      return left == null && right == null;
    }

    @Override
    public int compareTo(HuffmanNode other) {
      return Integer.compare(this.frequency, other.frequency);
    }
  }

  /**
   * @brief Builds Huffman tree from character frequencies.
   * @details Uses a priority queue to build optimal encoding tree.
   *
   * @param frequencies Map of character frequencies
   * @return Root of Huffman tree
   */
  public static HuffmanNode buildHuffmanTree(Map<Character, Integer> frequencies) {
    if (frequencies == null || frequencies.isEmpty()) {
      return null;
    }

    PriorityQueue<HuffmanNode> pq = new PriorityQueue<>();

    // Create leaf nodes for each character
    for (Map.Entry<Character, Integer> entry : frequencies.entrySet()) {
      pq.offer(new HuffmanNode(entry.getKey(), entry.getValue()));
    }

    // Build tree by combining nodes
    while (pq.size() > 1) {
      HuffmanNode left = pq.poll();
      HuffmanNode right = pq.poll();
      HuffmanNode parent = new HuffmanNode(
        left.frequency + right.frequency, left, right
      );
      pq.offer(parent);
    }

    return pq.poll();
  }

  /**
   * @brief Generates Huffman codes from tree.
   * @details Traverses tree to generate binary codes for each character.
   *
   * @param root Root of Huffman tree
   * @param code Current code string
   * @param huffmanCodes Map to store character codes
   */
  private static void generateCodesHelper(HuffmanNode root, String code,
                                          Map<Character, String> huffmanCodes) {
    if (root == null) {
      return;
    }

    if (root.isLeaf()) {
      huffmanCodes.put(root.character, code.isEmpty() ? "0" : code);
      return;
    }

    generateCodesHelper(root.left, code + "0", huffmanCodes);
    generateCodesHelper(root.right, code + "1", huffmanCodes);
  }

  /**
   * @brief Generates Huffman codes for all characters.
   *
   * @param root Root of Huffman tree
   * @return Map of character to Huffman code
   */
  public static Map<Character, String> generateHuffmanCodes(HuffmanNode root) {
    Map<Character, String> huffmanCodes = new HashMap<>();

    if (root != null) {
      generateCodesHelper(root, "", huffmanCodes);
    }

    return huffmanCodes;
  }

  /**
   * @brief Compresses password using Huffman coding.
   * @details Returns binary string representation of compressed password.
   *
   * @param password Password to compress
   * @return Compressed password as binary string, or empty if input is invalid
   */
  public static String compressPassword(String password) {
    if (password == null || password.isEmpty()) {
      return "";
    }

    // Calculate character frequencies
    Map<Character, Integer> frequencies = new HashMap<>();

    for (char c : password.toCharArray()) {
      frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
    }

    // Build Huffman tree
    HuffmanNode root = buildHuffmanTree(frequencies);

    if (root == null) {
      return "";
    }

    // Generate codes
    Map<Character, String> codes = generateHuffmanCodes(root);
    // Encode password
    StringBuilder compressed = new StringBuilder();

    for (char c : password.toCharArray()) {
      compressed.append(codes.get(c));
    }

    return compressed.toString();
  }

  /**
   * @brief Decompresses password using Huffman tree.
   * @details Traverses tree using binary string to decode original password.
   *
   * @param compressed Compressed binary string
   * @param root Root of Huffman tree
   * @return Decompressed password, or empty if input is invalid
   */
  public static String decompressPassword(String compressed, HuffmanNode root) {
    if (compressed == null || compressed.isEmpty() || root == null) {
      return "";
    }

    StringBuilder decompressed = new StringBuilder();

    // Special case: single character tree (root is a leaf)
    if (root.isLeaf()) {
      // Each bit represents one occurrence of the character
      for (int i = 0; i < compressed.length(); i++) {
        decompressed.append(root.character);
      }

      return decompressed.toString();
    }

    HuffmanNode current = root;

    for (char bit : compressed.toCharArray()) {
      if (bit == '0') {
        current = current.left;
      } else if (bit == '1') {
        current = current.right;
      }

      if (current != null && current.isLeaf()) {
        decompressed.append(current.character);
        current = root;
      }
    }

    return decompressed.toString();
  }

  /**
   * @brief Calculates compression ratio.
   * @details Compares original size (8 bits per char) vs compressed size.
   *
   * @param original Original password
   * @param compressed Compressed binary string
   * @return Compression ratio (0-100%), or 0 if invalid
   */
  public static double getCompressionRatio(String original, String compressed) {
    if (original == null || original.isEmpty() ||
        compressed == null || compressed.isEmpty()) {
      return 0.0;
    }

    int originalBits = original.length() * 8;
    int compressedBits = compressed.length();
    return (1.0 - ((double) compressedBits / originalBits)) * 100.0;
  }
}
