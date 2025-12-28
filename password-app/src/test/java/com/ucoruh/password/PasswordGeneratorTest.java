package com.ucoruh.password;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @brief Unit tests for the PasswordGenerator class.
 */
public class PasswordGeneratorTest {

  private final PrintStream originalOut = System.out;
  private ByteArrayOutputStream outputStream;

  @Before
  public void setUp() {
    outputStream = new ByteArrayOutputStream();
    System.setOut(new PrintStream(outputStream));
  }

  @After
  public void tearDown() {
    System.setOut(originalOut);
  }

  /**
   * Test to verify the character set constants are correctly defined.
   * This test uses reflection to access the private static fields.
   */
  @Test
  public void testCharacterSetConstants() throws Exception {
    // Use reflection to access private static fields
    Field uppercaseField = PasswordGenerator.class.getDeclaredField("UPPERCASE_CHARS");
    Field lowercaseField = PasswordGenerator.class.getDeclaredField("LOWERCASE_CHARS");
    Field digitField = PasswordGenerator.class.getDeclaredField("DIGIT_CHARS");
    Field specialField = PasswordGenerator.class.getDeclaredField("SPECIAL_CHARS");
    Field charactersField = PasswordGenerator.class.getDeclaredField("CHARACTERS");

    // Make the fields accessible
    uppercaseField.setAccessible(true);
    lowercaseField.setAccessible(true);
    digitField.setAccessible(true);
    specialField.setAccessible(true);
    charactersField.setAccessible(true);

    // Get the values
    String uppercase = (String) uppercaseField.get(null);
    String lowercase = (String) lowercaseField.get(null);
    String digits = (String) digitField.get(null);
    String special = (String) specialField.get(null);
    String characters = (String) charactersField.get(null);

    // Verify the contents
    assertEquals("ABCDEFGHIJKLMNOPQRSTUVWXYZ", uppercase);
    assertEquals("abcdefghijklmnopqrstuvwxyz", lowercase);
    assertEquals("0123456789", digits);
    assertEquals("!@#$%^&*()_-+=<>?/[]{}|", special);

    // Verify that CHARACTERS is the concatenation of the other sets
    assertEquals(uppercase + lowercase + digits + special, characters);
  }

  /**
   * Test to verify that each character set is used properly when generating passwords.
   */
  @Test
  public void testCharacterSetsUsage() throws Exception {
    // Get access to the character sets via reflection
    Field uppercaseField = PasswordGenerator.class.getDeclaredField("UPPERCASE_CHARS");
    Field lowercaseField = PasswordGenerator.class.getDeclaredField("LOWERCASE_CHARS");
    Field digitField = PasswordGenerator.class.getDeclaredField("DIGIT_CHARS");
    Field specialField = PasswordGenerator.class.getDeclaredField("SPECIAL_CHARS");

    uppercaseField.setAccessible(true);
    lowercaseField.setAccessible(true);
    digitField.setAccessible(true);
    specialField.setAccessible(true);

    String uppercase = (String) uppercaseField.get(null);
    String lowercase = (String) lowercaseField.get(null);
    String digits = (String) digitField.get(null);
    String special = (String) specialField.get(null);

    // Generate a password with only lowercase
    String lowercasePassword = PasswordGenerator.generatePassword(20, false, true, false, false);

    for (char c : lowercasePassword.toCharArray()) {
      assertTrue("Character should be in lowercase set", lowercase.indexOf(c) >= 0);
    }

    // Generate a password with only digits
    String digitPassword = PasswordGenerator.generatePassword(20, false, false, true, false);

    for (char c : digitPassword.toCharArray()) {
      assertTrue("Character should be in digit set", digits.indexOf(c) >= 0);
    }

    // Generate a password with only special characters
    String specialPassword = PasswordGenerator.generatePassword(20, false, false, false, true);

    for (char c : specialPassword.toCharArray()) {
      assertTrue("Character should be in special character set", special.indexOf(c) >= 0);
    }

    // Generate a password with all character types
    String allCharsPassword = PasswordGenerator.generatePassword(100);

    boolean hasUppercase = false;
    boolean hasLowercase = false;
    boolean hasDigit = false;
    boolean hasSpecial = false;

    for (char c : allCharsPassword.toCharArray()) {
      if (uppercase.indexOf(c) >= 0) hasUppercase = true;
      else if (lowercase.indexOf(c) >= 0) hasLowercase = true;
      else if (digits.indexOf(c) >= 0) hasDigit = true;
      else if (special.indexOf(c) >= 0) hasSpecial = true;
    }

    assertTrue("Password should include characters from uppercase set", hasUppercase);
    assertTrue("Password should include characters from lowercase set", hasLowercase);
    assertTrue("Password should include characters from digit set", hasDigit);
    assertTrue("Password should include characters from special character set", hasSpecial);
  }

  /**
   * Tests the generate method with user input for length.
   */
  @Test
  public void testGenerate() {
    Scanner scanner = new Scanner("12\n");
    PasswordGenerator.generate(scanner);
    String output = outputStream.toString();
    assertTrue(output.contains("Enter desired password length"));
    assertTrue(output.contains("Generated Password:"));
  }

  /**
   * Tests the interactive generate method with explicit Scanner input.
   */
  @Test
  public void testGenerateWithScanner() {
    String input = "8\n";
    Scanner scanner = new Scanner(input);
    PasswordGenerator.generate(scanner);
    String output = outputStream.toString();
    assertFalse(output.isEmpty());
    assertTrue(output.contains("Generated Password:"));
  }

  /**
   * Tests that generatePassword creates passwords of the requested length.
   */
  @Test
  public void testGeneratePasswordLength() {
    // Test different lengths
    int[] testLengths = {5, 10, 15, 20};

    for (int length : testLengths) {
      String password = PasswordGenerator.generatePassword(length);
      assertEquals("Generated password should be of requested length", length, password.length());
    }
  }

  /**
   * Tests that generatePassword creates different passwords on consecutive calls.
   */
  @Test
  public void testGeneratePasswordUniqueness() {
    int length = 10;
    String password1 = PasswordGenerator.generatePassword(length);
    String password2 = PasswordGenerator.generatePassword(length);
    String password3 = PasswordGenerator.generatePassword(length);
    // Check all are different (this is statistical, but highly likely with secure RNG)
    assertFalse("Consecutive passwords should be different",
                password1.equals(password2) && password2.equals(password3));
  }

  /**
   * Tests that generatePassword creates passwords with expected character classes.
   */
  @Test
  public void testGeneratePasswordCharacterClasses() {
    // Generate a reasonably long password to expect all character classes
    String password = PasswordGenerator.generatePassword(100);
    // Check for presence of different character classes
    boolean hasUppercase = false;
    boolean hasLowercase = false;
    boolean hasDigit = false;
    boolean hasSpecial = false;

    for (char c : password.toCharArray()) {
      if (Character.isUpperCase(c)) hasUppercase = true;
      else if (Character.isLowerCase(c)) hasLowercase = true;
      else if (Character.isDigit(c)) hasDigit = true;
      else hasSpecial = true;
    }

    assertTrue("Password should contain uppercase letters", hasUppercase);
    assertTrue("Password should contain lowercase letters", hasLowercase);
    assertTrue("Password should contain digits", hasDigit);
    assertTrue("Password should contain special characters", hasSpecial);
  }

  /**
   * Tests handling of zero-length password requests.
   */
  @Test
  public void testGeneratePasswordZeroLength() {
    String password = PasswordGenerator.generatePassword(0);
    assertEquals("Zero-length password should be empty string", 0, password.length());
  }

  /**
   * Tests handling of negative-length password requests.
   */
  @Test
  public void testGeneratePasswordNegativeLength() {
    String password = PasswordGenerator.generatePassword(-5);
    assertEquals("Negative-length password should be empty string", 0, password.length());
  }

  /**
   * Tests that generate method handles number format exception gracefully.
   */
  @Test
  public void testGenerateWithInvalidInput() {
    // Simulate invalid input (non-numeric)
    String input = "not-a-number\n";
    Scanner scanner = new Scanner(input);
    // This should not throw an exception now, as it's caught internally
    PasswordGenerator.generate(scanner);
    String output = outputStream.toString();
    assertTrue("Output should contain error message",
               output.contains("Invalid input") || output.contains("valid number"));
  }

  /**
   * Tests the generatePassword method with only uppercase letters.
   */
  @Test
  public void testGeneratePasswordWithOnlyUppercase() {
    String password = PasswordGenerator.generatePassword(20, true, false, false, false);
    boolean onlyUppercase = true;

    for (char c : password.toCharArray()) {
      if (!Character.isUpperCase(c)) {
        onlyUppercase = false;
        break;
      }
    }

    assertTrue("Password should contain only uppercase letters", onlyUppercase);
    assertEquals("Password should be of requested length", 20, password.length());
  }

  /**
   * Tests the generatePassword method with only lowercase letters.
   */
  @Test
  public void testGeneratePasswordWithOnlyLowercase() {
    String password = PasswordGenerator.generatePassword(20, false, true, false, false);
    boolean onlyLowercase = true;

    for (char c : password.toCharArray()) {
      if (!Character.isLowerCase(c)) {
        onlyLowercase = false;
        break;
      }
    }

    assertTrue("Password should contain only lowercase letters", onlyLowercase);
    assertEquals("Password should be of requested length", 20, password.length());
  }

  /**
   * Tests the generatePassword method with only digits.
   */
  @Test
  public void testGeneratePasswordWithOnlyDigits() {
    String password = PasswordGenerator.generatePassword(20, false, false, true, false);
    boolean onlyDigits = true;

    for (char c : password.toCharArray()) {
      if (!Character.isDigit(c)) {
        onlyDigits = false;
        break;
      }
    }

    assertTrue("Password should contain only digits", onlyDigits);
    assertEquals("Password should be of requested length", 20, password.length());
  }

  /**
   * Tests the generatePassword method with only special characters.
   */
  @Test
  public void testGeneratePasswordWithOnlySpecial() {
    String password = PasswordGenerator.generatePassword(20, false, false, false, true);
    boolean onlySpecial = true;

    for (char c : password.toCharArray()) {
      if (Character.isLetter(c) || Character.isDigit(c)) {
        onlySpecial = false;
        break;
      }
    }

    assertTrue("Password should contain only special characters", onlySpecial);
    assertEquals("Password should be of requested length", 20, password.length());
  }

  /**
   * Tests the generatePassword method with mixed character types.
   */
  @Test
  public void testGeneratePasswordWithMixedCharTypes() {
    // Test with uppercase and digits
    String password1 = PasswordGenerator.generatePassword(20, true, false, true, false);
    boolean hasUppercase1 = false;
    boolean hasDigit1 = false;
    boolean hasInvalid1 = false;

    for (char c : password1.toCharArray()) {
      if (Character.isUpperCase(c)) hasUppercase1 = true;
      else if (Character.isDigit(c)) hasDigit1 = true;
      else if (Character.isLowerCase(c) || !Character.isLetterOrDigit(c)) hasInvalid1 = true;
    }

    assertTrue("Password should contain uppercase letters", hasUppercase1);
    assertTrue("Password should contain digits", hasDigit1);
    assertFalse("Password should not contain lowercase or special chars", hasInvalid1);
    // Test with lowercase and special
    String password2 = PasswordGenerator.generatePassword(20, false, true, false, true);
    boolean hasLowercase2 = false;
    boolean hasSpecial2 = false;
    boolean hasInvalid2 = false;

    for (char c : password2.toCharArray()) {
      if (Character.isLowerCase(c)) hasLowercase2 = true;
      else if (!Character.isLetterOrDigit(c)) hasSpecial2 = true;
      else if (Character.isUpperCase(c) || Character.isDigit(c)) hasInvalid2 = true;
    }

    assertTrue("Password should contain lowercase letters", hasLowercase2);
    assertTrue("Password should contain special characters", hasSpecial2);
    assertFalse("Password should not contain uppercase or digits", hasInvalid2);
  }

  /**
   * Tests that the guaranteed inclusion of at least one character from each selected type works.
   */
  @Test
  public void testGuaranteedCharacterInclusion() {
    // A short password with all types selected should include at least one of each type
    String password = PasswordGenerator.generatePassword(4, true, true, true, true);
    boolean hasUppercase = false;
    boolean hasLowercase = false;
    boolean hasDigit = false;
    boolean hasSpecial = false;

    for (char c : password.toCharArray()) {
      if (Character.isUpperCase(c)) hasUppercase = true;
      else if (Character.isLowerCase(c)) hasLowercase = true;
      else if (Character.isDigit(c)) hasDigit = true;
      else hasSpecial = true;
    }

    assertTrue("Password should contain at least one uppercase letter", hasUppercase);
    assertTrue("Password should contain at least one lowercase letter", hasLowercase);
    assertTrue("Password should contain at least one digit", hasDigit);
    assertTrue("Password should contain at least one special character", hasSpecial);
  }

  /**
   * Tests that when no character type is selected, lowercase is used by default.
   */
  @Test
  public void testNoCharacterTypeSelected() {
    String password = PasswordGenerator.generatePassword(10, false, false, false, false);
    boolean onlyLowercase = true;

    for (char c : password.toCharArray()) {
      if (!Character.isLowerCase(c)) {
        onlyLowercase = false;
        break;
      }
    }

    assertTrue("When no character type is selected, default to lowercase", onlyLowercase);
  }

  // ========== KMP STRING MATCHING TESTS ==========

  /**
   * Tests basic KMP search functionality.
   */
  @Test
  public void testKmpSearchBasic() {
    assertEquals(0, PasswordGenerator.kmpSearch("hello", "hello"));
    assertEquals(0, PasswordGenerator.kmpSearch("hello world", "hello"));
    assertEquals(6, PasswordGenerator.kmpSearch("hello world", "world"));
    assertEquals(2, PasswordGenerator.kmpSearch("ababcabcab", "abc"));
  }

  /**
   * Tests KMP search with pattern not found.
   */
  @Test
  public void testKmpSearchNotFound() {
    assertEquals(-1, PasswordGenerator.kmpSearch("hello", "xyz"));
    assertEquals(-1, PasswordGenerator.kmpSearch("abc", "abcd"));
    assertEquals(-1, PasswordGenerator.kmpSearch("test", "testing"));
  }

  /**
   * Tests KMP search with null and empty inputs.
   */
  @Test
  public void testKmpSearchNullEmpty() {
    assertEquals(-1, PasswordGenerator.kmpSearch(null, "test"));
    assertEquals(-1, PasswordGenerator.kmpSearch("test", null));
    assertEquals(-1, PasswordGenerator.kmpSearch("test", ""));
    assertEquals(-1, PasswordGenerator.kmpSearch("", "test"));
  }

  /**
   * Tests KMP search with repeating patterns.
   */
  @Test
  public void testKmpSearchRepeating() {
    assertEquals(0, PasswordGenerator.kmpSearch("aaaa", "aa"));
    assertEquals(0, PasswordGenerator.kmpSearch("abababab", "abab"));
    assertEquals(0, PasswordGenerator.kmpSearch("123123123", "123123"));
    assertEquals(2, PasswordGenerator.kmpSearch("ab123ab", "123"));
  }

  /**
   * Tests containsPattern method.
   */
  @Test
  public void testContainsPattern() {
    assertTrue(PasswordGenerator.containsPattern("Password123", "123"));
    assertTrue(PasswordGenerator.containsPattern("admin@123", "@123"));
    assertFalse(PasswordGenerator.containsPattern("SecurePass!", "123"));
    assertFalse(PasswordGenerator.containsPattern("test", "testing"));
  }

  /**
   * Tests weak pattern detection with common weak patterns.
   */
  @Test
  public void testIsWeakPatternCommon() {
    assertTrue(PasswordGenerator.isWeakPattern("password"));
    assertTrue(PasswordGenerator.isWeakPattern("Password123"));
    assertTrue(PasswordGenerator.isWeakPattern("qwerty"));
    assertTrue(PasswordGenerator.isWeakPattern("admin"));
    assertTrue(PasswordGenerator.isWeakPattern("12345"));
    assertTrue(PasswordGenerator.isWeakPattern("abc123"));
  }

  /**
   * Tests weak pattern detection with sequential numbers.
   */
  @Test
  public void testIsWeakPatternSequential() {
    assertTrue(PasswordGenerator.isWeakPattern("abc123xyz"));
    assertTrue(PasswordGenerator.isWeakPattern("test456"));
    assertTrue(PasswordGenerator.isWeakPattern("789abc"));
    assertFalse(PasswordGenerator.isWeakPattern("135")); // Not sequential
    assertFalse(PasswordGenerator.isWeakPattern("147")); // Not sequential
  }

  /**
   * Tests weak pattern detection with repeated characters.
   */
  @Test
  public void testIsWeakPatternRepeated() {
    assertTrue(PasswordGenerator.isWeakPattern("aaa"));
    assertTrue(PasswordGenerator.isWeakPattern("test111"));
    assertTrue(PasswordGenerator.isWeakPattern("xxx123"));
    assertFalse(PasswordGenerator.isWeakPattern("aa")); // Only 2 repeated
    assertFalse(PasswordGenerator.isWeakPattern("a1b2c3"));
  }

  /**
   * Tests weak pattern with null and empty.
   */
  @Test
  public void testIsWeakPatternNullEmpty() {
    assertTrue(PasswordGenerator.isWeakPattern(null));
    assertTrue(PasswordGenerator.isWeakPattern(""));
  }

  /**
   * Tests strong passwords.
   */
  @Test
  public void testStrongPasswords() {
    assertFalse(PasswordGenerator.isWeakPattern("K7!mX@9pL"));
    assertFalse(PasswordGenerator.isWeakPattern("Xy0ng#Pa5s"));
    assertFalse(PasswordGenerator.isWeakPattern("Z@x1B!9m"));
    assertFalse(PasswordGenerator.isWeakPattern("Mj#8Kp2@Lx"));
  }

  /**
   * Tests generateStrongPassword method.
   */
  @Test
  public void testGenerateStrongPassword() {
    String password = PasswordGenerator.generateStrongPassword(12);
    assertNotNull(password);
    assertEquals(12, password.length());
    assertFalse("Generated password should not contain weak patterns",
                PasswordGenerator.isWeakPattern(password));
  }

  /**
   * Tests KMP with single character pattern.
   */
  @Test
  public void testKmpSearchSingleChar() {
    assertEquals(0, PasswordGenerator.kmpSearch("a", "a"));
    assertEquals(2, PasswordGenerator.kmpSearch("abc", "c"));
    assertEquals(-1, PasswordGenerator.kmpSearch("abc", "x"));
  }

  /**
   * Tests KMP with pattern at the end.
   */
  @Test
  public void testKmpSearchAtEnd() {
    assertEquals(7, PasswordGenerator.kmpSearch("testing123", "123"));
    assertEquals(5, PasswordGenerator.kmpSearch("helloworld", "world"));
  }

  /**
   * Tests weak pattern case insensitivity.
   */
  @Test
  public void testWeakPatternCaseInsensitive() {
    assertTrue(PasswordGenerator.isWeakPattern("PASSWORD"));
    assertTrue(PasswordGenerator.isWeakPattern("PaSsWoRd"));
    assertTrue(PasswordGenerator.isWeakPattern("ADMIN123"));
    assertTrue(PasswordGenerator.isWeakPattern("Admin"));
  }

  // ========== HUFFMAN CODING TESTS ==========

  /**
   * Tests building Huffman tree from character frequencies.
   */
  @Test
  public void testBuildHuffmanTree() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('a', 5);
    frequencies.put('b', 9);
    frequencies.put('c', 12);
    frequencies.put('d', 13);
    frequencies.put('e', 16);
    frequencies.put('f', 45);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    assertNotNull("Huffman tree root should not be null", root);
    assertEquals("Root frequency should be sum of all frequencies", 100, root.frequency);
    assertFalse("Root should not be a leaf", root.isLeaf());
  }

  /**
   * Tests building Huffman tree with empty frequencies.
   */
  @Test
  public void testBuildHuffmanTreeEmpty() {
    Map<Character, Integer> frequencies = new HashMap<>();
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    assertNull("Huffman tree should be null for empty frequencies", root);
  }

  /**
   * Tests building Huffman tree with null frequencies.
   */
  @Test
  public void testBuildHuffmanTreeNull() {
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(null);
    assertNull("Huffman tree should be null for null frequencies", root);
  }

  /**
   * Tests building Huffman tree with single character.
   */
  @Test
  public void testBuildHuffmanTreeSingleChar() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('a', 10);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    assertNotNull("Huffman tree root should not be null", root);
    assertTrue("Root should be a leaf for single character", root.isLeaf());
    assertEquals("Root should have correct character", 'a', root.character);
    assertEquals("Root should have correct frequency", 10, root.frequency);
  }

  /**
   * Tests generating Huffman codes from tree.
   */
  @Test
  public void testGenerateHuffmanCodes() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('a', 5);
    frequencies.put('b', 9);
    frequencies.put('c', 12);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    Map<Character, String> codes = PasswordGenerator.generateHuffmanCodes(root);
    assertNotNull("Huffman codes should not be null", codes);
    assertEquals("Should have codes for all characters", 3, codes.size());
    assertTrue("Should have code for 'a'", codes.containsKey('a'));
    assertTrue("Should have code for 'b'", codes.containsKey('b'));
    assertTrue("Should have code for 'c'", codes.containsKey('c'));

    // Verify codes are binary strings
    for (String code : codes.values()) {
      assertTrue("Code should not be empty", code.length() > 0);

      for (char c : code.toCharArray()) {
        assertTrue("Code should only contain 0 or 1", c == '0' || c == '1');
      }
    }
  }

  /**
   * Tests generating Huffman codes with null root.
   */
  @Test
  public void testGenerateHuffmanCodesNull() {
    Map<Character, String> codes = PasswordGenerator.generateHuffmanCodes(null);
    assertNotNull("Huffman codes should not be null", codes);
    assertTrue("Huffman codes should be empty for null root", codes.isEmpty());
  }

  /**
   * Tests generating Huffman codes with single character.
   */
  @Test
  public void testGenerateHuffmanCodesSingleChar() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('x', 10);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    Map<Character, String> codes = PasswordGenerator.generateHuffmanCodes(root);
    assertNotNull("Huffman codes should not be null", codes);
    assertEquals("Should have one code", 1, codes.size());
    assertEquals("Single character should have code '0'", "0", codes.get('x'));
  }

  /**
   * Tests password compression using Huffman coding.
   */
  @Test
  public void testCompressPassword() {
    String password = "hello";
    String compressed = PasswordGenerator.compressPassword(password);
    assertNotNull("Compressed password should not be null", compressed);
    assertFalse("Compressed password should not be empty", compressed.isEmpty());

    // Verify it's a binary string
    for (char c : compressed.toCharArray()) {
      assertTrue("Compressed should only contain 0 or 1", c == '0' || c == '1');
    }
  }

  /**
   * Tests compression with null password.
   */
  @Test
  public void testCompressPasswordNull() {
    String compressed = PasswordGenerator.compressPassword(null);
    assertEquals("Compressed should be empty for null", "", compressed);
  }

  /**
   * Tests compression with empty password.
   */
  @Test
  public void testCompressPasswordEmpty() {
    String compressed = PasswordGenerator.compressPassword("");
    assertEquals("Compressed should be empty for empty password", "", compressed);
  }

  /**
   * Tests password decompression using Huffman coding.
   */
  @Test
  public void testDecompressPassword() {
    String password = "hello";
    // Build tree from password
    Map<Character, Integer> frequencies = new HashMap<>();

    for (char c : password.toCharArray()) {
      frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
    }

    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    // Compress and decompress
    String compressed = PasswordGenerator.compressPassword(password);
    String decompressed = PasswordGenerator.decompressPassword(compressed, root);
    assertEquals("Decompressed should match original", password, decompressed);
  }

  /**
   * Tests decompression with null compressed string.
   */
  @Test
  public void testDecompressPasswordNull() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('a', 1);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    String decompressed = PasswordGenerator.decompressPassword(null, root);
    assertEquals("Decompressed should be empty for null", "", decompressed);
  }

  /**
   * Tests decompression with empty compressed string.
   */
  @Test
  public void testDecompressPasswordEmpty() {
    Map<Character, Integer> frequencies = new HashMap<>();
    frequencies.put('a', 1);
    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    String decompressed = PasswordGenerator.decompressPassword("", root);
    assertEquals("Decompressed should be empty for empty compressed", "", decompressed);
  }

  /**
   * Tests decompression with null root.
   */
  @Test
  public void testDecompressPasswordNullRoot() {
    String decompressed = PasswordGenerator.decompressPassword("010101", null);
    assertEquals("Decompressed should be empty for null root", "", decompressed);
  }

  /**
   * Tests compression/decompression with repeated characters.
   */
  @Test
  public void testHuffmanWithRepeatedChars() {
    String password = "aaabbbccc";
    Map<Character, Integer> frequencies = new HashMap<>();

    for (char c : password.toCharArray()) {
      frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
    }

    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    String compressed = PasswordGenerator.compressPassword(password);
    String decompressed = PasswordGenerator.decompressPassword(compressed, root);
    assertEquals("Decompressed should match original", password, decompressed);
  }

  /**
   * Tests compression/decompression with single character repeated.
   */
  @Test
  public void testHuffmanSingleCharRepeated() {
    String password = "aaaa";
    Map<Character, Integer> frequencies = new HashMap<>();

    for (char c : password.toCharArray()) {
      frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
    }

    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    String compressed = PasswordGenerator.compressPassword(password);
    String decompressed = PasswordGenerator.decompressPassword(compressed, root);
    assertEquals("Decompressed should match original", password, decompressed);
  }

  /**
   * Tests compression ratio calculation.
   */
  @Test
  public void testCompressionRatio() {
    String original = "hello";
    String compressed = PasswordGenerator.compressPassword(original);
    double ratio = PasswordGenerator.getCompressionRatio(original, compressed);
    assertTrue("Compression ratio should be non-negative", ratio >= 0);
    assertTrue("Compression ratio should be less than or equal to 100", ratio <= 100);
  }

  /**
   * Tests compression ratio with null original.
   */
  @Test
  public void testCompressionRatioNullOriginal() {
    double ratio = PasswordGenerator.getCompressionRatio(null, "010101");
    assertEquals("Ratio should be 0 for null original", 0.0, ratio, 0.001);
  }

  /**
   * Tests compression ratio with empty original.
   */
  @Test
  public void testCompressionRatioEmptyOriginal() {
    double ratio = PasswordGenerator.getCompressionRatio("", "010101");
    assertEquals("Ratio should be 0 for empty original", 0.0, ratio, 0.001);
  }

  /**
   * Tests compression ratio with null compressed.
   */
  @Test
  public void testCompressionRatioNullCompressed() {
    double ratio = PasswordGenerator.getCompressionRatio("hello", null);
    assertEquals("Ratio should be 0 for null compressed", 0.0, ratio, 0.001);
  }

  /**
   * Tests compression ratio with empty compressed.
   */
  @Test
  public void testCompressionRatioEmptyCompressed() {
    double ratio = PasswordGenerator.getCompressionRatio("hello", "");
    assertEquals("Ratio should be 0 for empty compressed", 0.0, ratio, 0.001);
  }

  /**
   * Tests Huffman with special characters.
   */
  @Test
  public void testHuffmanWithSpecialChars() {
    String password = "p@ssw0rd!";
    Map<Character, Integer> frequencies = new HashMap<>();

    for (char c : password.toCharArray()) {
      frequencies.put(c, frequencies.getOrDefault(c, 0) + 1);
    }

    PasswordGenerator.HuffmanNode root = PasswordGenerator.buildHuffmanTree(frequencies);
    String compressed = PasswordGenerator.compressPassword(password);
    String decompressed = PasswordGenerator.decompressPassword(compressed, root);
    assertEquals("Decompressed should match original with special chars", password, decompressed);
  }
}
