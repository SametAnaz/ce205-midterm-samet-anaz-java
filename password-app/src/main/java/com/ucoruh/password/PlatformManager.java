/**
 * @file PlatformManager.java
 * @class PlatformManager
 * @brief Class for Multi-Platform Compatibility management.
 * @author Password Manager Team
 * @version 1.0
 *
 * This class provides functionality to manage and display platform-specific features
 * and compatibility information.
 */
package com.ucoruh.password;

import java.util.Arrays;
import java.util.List;

/**
 * @brief Class for Multi-Platform Compatibility.
 * @details This class provides methods for platform detection and compatibility information.
 */
public class PlatformManager {

  /**
   * @brief List of supported platforms.
   * @details Contains Windows, macOS, Linux, Android, and iOS.
   */
  private static final List<String> SUPPORTED_PLATFORMS =
    Arrays.asList("Windows", "macOS", "Linux", "Android", "iOS");

  /**
   * @brief Displays supported platforms.
   *
   * This method prints a list of supported platforms including Windows, macOS, Linux,
   * Android, and iOS to the standard output.
   */
  public static void showPlatforms() {
    System.out.println("Supported platforms: " + String.join(", ", SUPPORTED_PLATFORMS));
  }

  /**
   * @brief Checks if a specific platform is supported.
   *
   * @param platform The platform name to check
   * @return true if the platform is supported, false otherwise
   */
  public static boolean isPlatformSupported(String platform) {
    return SUPPORTED_PLATFORMS.contains(platform);
  }

  /**
   * @brief Gets the current OS name.
   *
   * @return The name of the current operating system
   */
  public static String getCurrentPlatform() {
    String osName = System.getProperty("os.name");

    if (osName.toLowerCase().contains("windows")) {
      return "Windows";
    } else if (osName.toLowerCase().contains("mac")) {
      return "macOS";
    } else if (osName.toLowerCase().contains("linux")) {
      return "Linux";
    } else {
      return "Unknown";
    }
  }

  /**
   * @brief Returns the number of supported platforms.
   *
   * @return The count of supported platforms
   */
  public static int getNumberOfSupportedPlatforms() {
    return SUPPORTED_PLATFORMS.size();
  }
}
