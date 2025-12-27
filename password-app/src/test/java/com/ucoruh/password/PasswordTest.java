package com.ucoruh.password;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

/**
 * Unit tests for the Password class including doubly linked list history tracking.
 */
public class PasswordTest {

  @Test
  public void testConstructorAndGetters() {
    Password password = new Password("gmail", "user1", "pass123");
    assertEquals("gmail", password.getService());
    assertEquals("user1", password.getUsername());
    assertEquals("pass123", password.getPassword());
  }

  @Test
  public void testSetters() {
    Password password = new Password("service", "user", "pass");
    password.setUsername("newuser");
    password.setPassword("newpass");
    assertEquals("newuser", password.getUsername());
    assertEquals("newpass", password.getPassword());
  }

  @Test
  public void testToString() {
    Password password = new Password("github", "dev", "secure");
    String result = password.toString();
    assertTrue(result.contains("github"));
    assertTrue(result.contains("dev"));
    assertTrue(result.contains("secure"));
  }

  // ========== DOUBLY LINKED LIST HISTORY TESTS ==========

  @Test
  public void testPasswordHistoryInitialization() {
    Password password = new Password("test", "user", "pass1");
    assertEquals(1, password.getHistorySize());
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertEquals(1, history.size());
    assertEquals("pass1", history.get(0).getPassword());
  }

  @Test
  public void testSetPasswordWithHistory() {
    Password password = new Password("test", "user", "pass1");
    password.setPasswordWithHistory("pass2");
    password.setPasswordWithHistory("pass3");
    assertEquals(3, password.getHistorySize());
    assertEquals("pass3", password.getPassword());
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertEquals("pass1", history.get(0).getPassword());
    assertEquals("pass2", history.get(1).getPassword());
    assertEquals("pass3", history.get(2).getPassword());
  }

  @Test
  public void testSetPasswordWithoutHistory() {
    Password password = new Password("test", "user", "pass1");
    password.setPassword("pass2");
    // Should not add to history
    assertEquals(1, password.getHistorySize());
    assertEquals("pass2", password.getPassword());
  }

  @Test
  public void testMultiplePasswordChanges() {
    Password password = new Password("test", "user", "initial");

    for (int i = 1; i <= 10; i++) {
      password.setPasswordWithHistory("pass" + i);
    }

    assertEquals(11, password.getHistorySize()); // initial + 10
    assertEquals("pass10", password.getPassword());
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertEquals("initial", history.get(0).getPassword());
    assertEquals("pass10", history.get(10).getPassword());
  }

  @Test
  public void testClearHistory() {
    Password password = new Password("test", "user", "pass1");
    password.setPasswordWithHistory("pass2");
    password.setPasswordWithHistory("pass3");
    assertEquals(3, password.getHistorySize());
    password.clearHistory();
    assertEquals(0, password.getHistorySize());
    assertTrue(password.getPasswordHistory().isEmpty());
  }

  @Test
  public void testHistoryTimestamps() throws InterruptedException {
    Password password = new Password("test", "user", "pass1");

    Thread.sleep(10); // Small delay to ensure different timestamps

    password.setPasswordWithHistory("pass2");

    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertEquals(2, history.size());

    // Check timestamps exist and are positive
    assertTrue(history.get(0).getTimestamp() > 0);
    assertTrue(history.get(1).getTimestamp() > 0);

    // Second timestamp should be greater than or equal to first
    assertTrue(history.get(1).getTimestamp() >= history.get(0).getTimestamp());
  }

  @Test
  public void testEmptyHistoryAfterClear() {
    Password password = new Password("test", "user", "pass1");
    password.clearHistory();
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertNotNull(history);
    assertEquals(0, history.size());
  }

  @Test
  public void testHistoryEntryGetters() {
    Password password = new Password("test", "user", "testpass");
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    Password.PasswordHistoryEntry entry = history.get(0);
    assertEquals("testpass", entry.getPassword());
    assertTrue(entry.getTimestamp() > 0);
  }

  @Test
  public void testLargeHistoryTraversal() {
    Password password = new Password("test", "user", "pass0");

    // Add 100 passwords
    for (int i = 1; i < 100; i++) {
      password.setPasswordWithHistory("pass" + i);
    }

    assertEquals(100, password.getHistorySize());
    List<Password.PasswordHistoryEntry> history = password.getPasswordHistory();
    assertEquals(100, history.size());

    // Verify all entries are in order
    for (int i = 0; i < 100; i++) {
      assertEquals("pass" + i, history.get(i).getPassword());
    }
  }

  @Test
  public void testHistoryIndependence() {
    Password pass1 = new Password("service1", "user", "pass1");
    Password pass2 = new Password("service2", "user", "pass2");
    pass1.setPasswordWithHistory("newpass1");
    pass1.setPasswordWithHistory("newpass2");
    pass2.setPasswordWithHistory("newpass3");
    assertEquals(3, pass1.getHistorySize());
    assertEquals(2, pass2.getHistorySize());
  }
}
