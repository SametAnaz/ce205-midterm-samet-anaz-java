# Plan: Password Manager - Algorithm Integration into Existing Classes & 90%+ Coverage

**YENİ YAKLAŞIM:** Yeni klasörler ve dosyalar oluşturmak yerine, eksik algoritmaları mevcut sınıflara entegre edeceğiz. Her algoritma, ilgili sınıfın sorumluluğuna uygun şekilde inner class veya private method olarak eklenecek.

## Mevcut Sınıf Analizi ve Sorumlulukları

### Mevcut Sınıflar ve İşlevleri:

1. **Password.java** - Data model (service, username, password) - SOLID: Single Responsibility
2. **PasswordManager.java** - Ana yönetim, HashMap kullanıyor, menu logic
3. **AuthManager.java** - Singleton, master password management, file I/O
4. **PasswordGenerator.java** - Utility class, random password generation
5. **EncryptionUtil.java** - Utility class, AES encryption/decryption, SHA-256 hashing
6. **FilePasswordStorage.java** - File-based storage, implements InterfacePasswordStorage
7. **DatabasePasswordStorage.java** - SQLite storage, implements InterfacePasswordStorage
8. **PasswordStorageFactory.java** - Factory pattern
9. **AutoLoginManager.java** - Auto-login management
10. **PlatformManager.java** - Platform detection utility
11. **StorageType.java** - Enum (FILE, DATABASE)
12. **InterfacePasswordStorage.java** - Storage interface
13. **GUI Classes** - Swing/JavaFX UI controllers

### Algoritma Entegrasyon Stratejisi:

| Algoritma | Entegre Edilecek Sınıf | Kullanım Amacı | Implementasyon Tipi |
|-----------|------------------------|----------------|---------------------|
| **1. Double Linked List** | `Password.java` | Password history tracking (previous passwords list) | Inner class `PasswordHistory` |
| **2. XOR Linked List** | `FilePasswordStorage.java` | Compact file storage optimization | Private inner class `XORLinkedStorage` |
| **3. Sparse Matrix** | `PasswordManager.java` | Access pattern matrix (service × timestamp) | Inner class `AccessMatrix` |
| **4. Stack** | `PasswordManager.java` | Undo/Redo operations for password changes | Inner class `CommandStack` |
| **5. Queue** | `PasswordManager.java` | Password change queue/scheduling | Inner class `ChangeQueue` |
| **6. Heap/Heap Sort** | `PasswordManager.java` | Most used services ranking, password strength sorting | Private methods `heapSort()`, `heapify()` |
| **7. Custom Hash Table** | `PasswordManager.java` | Replace HashMap with custom implementation | Inner class `CustomHashTable<K,V>` |
| **8. BFS/DFS Graph** | `PasswordManager.java` | Service dependency graph, related services | Inner class `ServiceGraph` |
| **9. Strongly Connected Components** | `PasswordManager.java` | Service clustering in graph | Private method in `ServiceGraph` |
| **10. KMP String Matching** | `PasswordGenerator.java` | Pattern detection in passwords, breach checking | Static method `kmpSearch()` |
| **11. Huffman Coding** | `FilePasswordStorage.java` | Password compression for backup/export | Inner class `HuffmanCompressor` |

## Steps (12 Major Steps - Revised for Integration Approach)

### Phase 1: Hazırlık ve Baseline (1 step)

### Phase 1: Hazırlık ve Baseline (1 step)

#### Step 1: Mevcut durumu kaydet ve analiz et
- Tüm testleri çalıştır: `mvn clean test` 
- JaCoCo raporu oluştur: `mvn jacoco:report`
- Mevcut sınıfların sorumluluklarını dokümante et
- Hangi sınıfa hangi algoritmanın ekleneceğini belirle
- Baseline coverage kaydet (current: ~63% average)
- Test altyapısını hazırla (TestDataGenerator, MockHelper SADECE GEREKIRSE)

### Phase 2: Password.java'ya Double Linked List Entegrasyonu (1 step)

#### Step 2: Password history tracking için DoublyLinkedList ekle
**Hedef Sınıf:** `Password.java`
**Implementasyon:**
```java
public class Password {
    private String service;
    private String username;
    private String password;
    
    // YENİ: Password history tracking
    private PasswordHistory history;
    
    /**
     * @brief Inner class for tracking password change history
     */
    private static class PasswordHistory {
        private static class Node {
            String password;
            long timestamp;
            Node prev;
            Node next;
            
            Node(String password, long timestamp) {
                this.password = password;
                this.timestamp = timestamp;
            }
        }
        
        private Node head;
        private Node tail;
        private int size;
        
        // Methods: addPassword(), getPreviousPasswords(), size(), clear()
    }
    
    // Public methods to interact with history
    public void setPasswordWithHistory(String newPassword) { ... }
    public List<String> getPasswordHistory() { ... }
    public int getHistorySize() { ... }
}
```
**Test Stratejisi:**
- `PasswordTest.java` içinde mevcut testleri koru
- Yeni history metodları için testler ekle
- Edge cases: empty history, single item, multiple adds, null passwords
- Target: Password.java coverage %100

### Phase 3: PasswordManager.java'ya Ana Algoritmalar Entegrasyonu (4 steps)

#### Step 3: Sparse Matrix ile Access Pattern Tracking
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // Existing fields...
    
    // YENİ: Access pattern tracking
    private AccessMatrix accessMatrix;
    
    /**
     * @brief Inner class for tracking service access patterns
     */
    private static class AccessMatrix {
        private Map<String, Map<Integer, Integer>> matrix; // service -> (hour -> count)
        
        public void recordAccess(String service, int hour) { ... }
        public Map<Integer, Integer> getAccessPattern(String service) { ... }
        public List<String> getMostAccessedServices(int topN) { ... }
    }
}
```
**Test:** `PasswordManagerTest.java` içinde yeni metodlar için test ekle
**Target:** PasswordManager coverage %53 → %75

#### Step 4: Stack için Undo/Redo Operations
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // YENİ: Command pattern with Stack
    private CommandStack undoStack;
    private CommandStack redoStack;
    
    /**
     * @brief Stack implementation for undo/redo
     */
    private static class CommandStack {
        private static class Node {
            Command command;
            Node next;
        }
        
        private Node top;
        private int size;
        
        public void push(Command cmd) { ... }
        public Command pop() { ... }
        public Command peek() { ... }
        public boolean isEmpty() { ... }
    }
    
    // Command interface
    private interface Command {
        void execute();
        void undo();
    }
    
    // Concrete commands: AddPasswordCommand, DeletePasswordCommand, UpdatePasswordCommand
    
    public void undo() { ... }
    public void redo() { ... }
}
```
**Test:** Undo/redo scenarios, stack boundary conditions
**Target:** PasswordManager coverage %75 → %85

#### Step 5: Custom Hash Table Implementation
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // DEĞIŞIKLIK: HashMap yerine CustomHashTable
    // private final Map<String, String> credentials; // EKSİ
    private final CustomHashTable<String, String> credentials; // YENİ
    
    /**
     * @brief Custom hash table with chaining collision resolution
     */
    private static class CustomHashTable<K, V> {
        private static class Entry<K, V> {
            K key;
            V value;
            Entry<K, V> next; // Chaining
            
            Entry(K key, V value) {
                this.key = key;
                this.value = value;
            }
        }
        
        private Entry<K, V>[] table;
        private int size;
        private int capacity;
        private static final int DEFAULT_CAPACITY = 16;
        private static final double LOAD_FACTOR = 0.75;
        
        public CustomHashTable() { ... }
        public void put(K key, V value) { ... }
        public V get(K key) { ... }
        public V remove(K key) { ... }
        public boolean containsKey(K key) { ... }
        private void resize() { ... }
        private int hash(K key) { ... }
        
        // Statistics methods
        public double getLoadFactor() { ... }
        public int getCollisionCount() { ... }
    }
}
```
**Test:** Collision handling, load factor, resize, null keys
**Target:** PasswordManager coverage %85 → %90

#### Step 6: Heap Sort için Service Ranking
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // YENİ: Service ranking by usage frequency
    public List<String> getMostUsedServices(int topN) {
        List<ServiceUsage> usages = collectUsageStats();
        heapSort(usages);
        return usages.stream()
            .limit(topN)
            .map(u -> u.service)
            .collect(Collectors.toList());
    }
    
    /**
     * @brief Heap sort implementation for service ranking
     */
    private static class ServiceUsage implements Comparable<ServiceUsage> {
        String service;
        int accessCount;
        
        @Override
        public int compareTo(ServiceUsage other) {
            return Integer.compare(this.accessCount, other.accessCount);
        }
    }
    
    private void heapSort(List<ServiceUsage> list) { ... }
    private void heapify(List<ServiceUsage> list, int n, int i) { ... }
}
```
**Test:** Sorting correctness, empty list, single item, duplicates
**Target:** PasswordManager coverage %90+ maintain

### Phase 4: PasswordGenerator.java'ya KMP String Matching (1 step)

#### Step 7: KMP ile Password Pattern Detection
**Hedef Sınıf:** `PasswordGenerator.java`
**Implementasyon:**
```java
public class PasswordGenerator {
    // Existing methods...
    
    /**
     * @brief KMP string matching for pattern detection
     */
    public static boolean containsPattern(String password, String pattern) {
        return kmpSearch(password, pattern) != -1;
    }
    
    /**
     * @brief KMP search implementation
     */
    private static int kmpSearch(String text, String pattern) {
        int[] lps = computeLPSArray(pattern);
        int i = 0; // index for text
        int j = 0; // index for pattern
        
        while (i < text.length()) {
            if (pattern.charAt(j) == text.charAt(i)) {
                i++;
                j++;
            }
            
            if (j == pattern.length()) {
                return i - j; // Pattern found
            } else if (i < text.length() && pattern.charAt(j) != text.charAt(i)) {
                if (j != 0) {
                    j = lps[j - 1];
                } else {
                    i++;
                }
            }
        }
        return -1; // Pattern not found
    }
    
    private static int[] computeLPSArray(String pattern) { ... }
    
    /**
     * @brief Check if password contains common weak patterns
     */
    public static boolean isWeakPattern(String password) {
        String[] weakPatterns = {"123", "abc", "qwerty", "password", "admin"};
        for (String pattern : weakPatterns) {
            if (containsPattern(password.toLowerCase(), pattern)) {
                return true;
            }
        }
        return false;
    }
}
```
**Test:** KMP correctness, pattern matching, weak pattern detection
**Target:** PasswordGenerator coverage %98.5 → %100

### Phase 5: FilePasswordStorage.java'ya XOR Linked List ve Huffman (2 steps)

#### Step 8: XOR Linked List ile Compact Storage
**Hedef Sınıf:** `FilePasswordStorage.java`
**Implementasyon:**
```java
public class FilePasswordStorage implements InterfacePasswordStorage {
    // Existing fields...
    
    // YENİ: Optional XOR linked list for memory-efficient storage
    private XORLinkedStorage xorStorage;
    
    /**
     * @brief XOR Linked List for memory-efficient password storage
     */
    private static class XORLinkedStorage {
        private static class XORNode {
            Password data;
            long link; // XOR of prev and next addresses
            
            XORNode(Password data) {
                this.data = data;
                this.link = 0;
            }
        }
        
        private XORNode head;
        private int size;
        
        public void add(Password password) { ... }
        public List<Password> getAllPasswords() { ... }
        public void clear() { ... }
        
        // XOR pointer arithmetic
        private long XOR(XORNode a, XORNode b) { ... }
    }
    
    // Optional: Use XOR storage for in-memory operations
    public void enableCompactMode() { ... }
}
```
**Test:** XOR linked list traversal, add/remove operations
**Target:** FilePasswordStorage coverage %94.6 → %98

#### Step 9: Huffman Coding ile Password Compression
**Hedef Sınıf:** `FilePasswordStorage.java`
**Implementasyon:**
```java
public class FilePasswordStorage implements InterfacePasswordStorage {
    // YENİ: Huffman compression for backup/export
    
    /**
     * @brief Huffman coding for password compression
     */
    private static class HuffmanCompressor {
        private static class HuffmanNode implements Comparable<HuffmanNode> {
            char ch;
            int frequency;
            HuffmanNode left;
            HuffmanNode right;
            
            @Override
            public int compareTo(HuffmanNode other) {
                return Integer.compare(this.frequency, other.frequency);
            }
        }
        
        public static String compress(String data) {
            Map<Character, Integer> freqMap = buildFrequencyMap(data);
            HuffmanNode root = buildHuffmanTree(freqMap);
            Map<Character, String> codeMap = generateCodes(root);
            return encode(data, codeMap);
        }
        
        public static String decompress(String compressed, HuffmanNode root) { ... }
        
        private static Map<Character, Integer> buildFrequencyMap(String data) { ... }
        private static HuffmanNode buildHuffmanTree(Map<Character, Integer> freqMap) { ... }
        private static Map<Character, String> generateCodes(HuffmanNode root) { ... }
        private static String encode(String data, Map<Character, String> codeMap) { ... }
    }
    
    /**
     * @brief Export passwords to compressed backup file
     */
    public void exportCompressed(String filename) throws Exception {
        List<Password> passwords = readAll();
        String data = serializePasswords(passwords);
        String compressed = HuffmanCompressor.compress(data);
        // Write to file
    }
    
    public void importCompressed(String filename) throws Exception { ... }
}
```
**Test:** Compression/decompression correctness, empty data, single char, all same chars
**Target:** FilePasswordStorage coverage %98 → %100

### Phase 6: PasswordManager.java'ya Graph Algorithms (1 step)

#### Step 10: Service Dependency Graph (BFS/DFS/SCC)
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // YENİ: Service dependency graph
    private ServiceGraph serviceGraph;
    
    /**
     * @brief Graph implementation for service relationships
     */
    private static class ServiceGraph {
        private Map<String, List<String>> adjacencyList;
        
        public ServiceGraph() {
            adjacencyList = new HashMap<>();
        }
        
        public void addService(String service) { ... }
        public void addDependency(String from, String to) { ... }
        
        /**
         * @brief BFS traversal for finding related services
         */
        public List<String> getRelatedServices(String service) {
            List<String> result = new ArrayList<>();
            Set<String> visited = new HashSet<>();
            Queue<String> queue = new LinkedList<>();
            
            queue.offer(service);
            visited.add(service);
            
            while (!queue.isEmpty()) {
                String current = queue.poll();
                result.add(current);
                
                List<String> neighbors = adjacencyList.getOrDefault(current, new ArrayList<>());
                for (String neighbor : neighbors) {
                    if (!visited.contains(neighbor)) {
                        visited.add(neighbor);
                        queue.offer(neighbor);
                    }
                }
            }
            
            return result;
        }
        
        /**
         * @brief DFS traversal for cycle detection
         */
        public boolean hasCycle() {
            Set<String> visited = new HashSet<>();
            Set<String> recursionStack = new HashSet<>();
            
            for (String service : adjacencyList.keySet()) {
                if (dfsCycleDetect(service, visited, recursionStack)) {
                    return true;
                }
            }
            return false;
        }
        
        private boolean dfsCycleDetect(String node, Set<String> visited, Set<String> recStack) { ... }
        
        /**
         * @brief Strongly Connected Components (Tarjan's algorithm)
         */
        public List<List<String>> findStronglyConnectedComponents() {
            List<List<String>> result = new ArrayList<>();
            Map<String, Integer> ids = new HashMap<>();
            Map<String, Integer> low = new HashMap<>();
            Set<String> onStack = new HashSet<>();
            Stack<String> stack = new Stack<>();
            int[] id = {0};
            
            for (String service : adjacencyList.keySet()) {
                if (!ids.containsKey(service)) {
                    tarjanDFS(service, ids, low, onStack, stack, id, result);
                }
            }
            
            return result;
        }
        
        private void tarjanDFS(String at, Map<String, Integer> ids, Map<String, Integer> low,
                              Set<String> onStack, Stack<String> stack, int[] id,
                              List<List<String>> result) { ... }
    }
    
    // Public methods to use graph
    public void buildServiceDependencyGraph() { ... }
    public List<String> getRelatedServices(String service) { ... }
    public List<List<String>> getServiceClusters() { ... }
}
```
**Test:** BFS/DFS correctness, cycle detection, SCC, disconnected graphs
**Target:** PasswordManager coverage %90 → %95+

### Phase 7: Queue Implementation (1 step)

#### Step 11: Password Change Queue
**Hedef Sınıf:** `PasswordManager.java`
**Implementasyon:**
```java
public class PasswordManager {
    // YENİ: Queue for scheduled password changes
    private ChangeQueue changeQueue;
    
    /**
     * @brief Queue implementation for password change scheduling
     */
    private static class ChangeQueue {
        private static class Node {
            PasswordChangeRequest request;
            Node next;
        }
        
        private Node front;
        private Node rear;
        private int size;
        
        public void enqueue(PasswordChangeRequest request) { ... }
        public PasswordChangeRequest dequeue() { ... }
        public PasswordChangeRequest peek() { ... }
        public boolean isEmpty() { ... }
        public int size() { ... }
    }
    
    /**
     * @brief Request for scheduled password change
     */
    private static class PasswordChangeRequest {
        String service;
        String newPassword;
        long scheduledTime;
        
        PasswordChangeRequest(String service, String newPassword, long scheduledTime) {
            this.service = service;
            this.newPassword = newPassword;
            this.scheduledTime = scheduledTime;
        }
    }
    
    public void schedulePasswordChange(String service, String newPassword, long delayMillis) { ... }
    public void processScheduledChanges() { ... }
}
```
**Test:** Queue operations, FIFO order, scheduled processing
**Target:** PasswordManager coverage maintain %95+

### Phase 8: Test Coverage Enhancement ve Final Validation (1 step)

#### Step 12: Eksik Coverage'ı %90+ Çıkar ve Validate Et
**Hedef Sınıflar:**
1. `DatabasePasswordStorageTest.java` - %27 → %90+ (SQL exceptions, encryption errors)
2. `AuthManagerTest.java` - %49 → %90+ (file errors, password change scenarios)
3. `PasswordAppTest.java` - %56 → %90+ (all menu paths, GUI mode)
4. `PlatformManagerTest.java` - %72 → %90+ (all platforms, edge cases)
5. `PasswordStorageFactoryTest.java` - %68 → %90+ (all factory paths)

**Test Stratejisi:**
- Her yeni algoritma için comprehensive unit tests
- Negative test cases (invalid inputs, exceptions)
- Boundary tests (empty, single item, max size)
- Integration tests (algoritmaların birlikte çalışması)

**Final Validation:**
```bash
mvn clean test jacoco:report
```
- Her class için %90+ coverage kontrolü
- JaCoCo HTML raporu: `target/site/jacoco/index.html`
- Doxygen: `doxygen Doxyfile`
- Tüm testler geçmeli (Failures: 0, Errors: 0)

**Build & Run Tests:**
```bash
7-build-app.bat  # Full build + coverage + doxygen
8-run-app.bat    # JAR execution
mvn site         # Comprehensive documentation
```

## Further Considerations

## Further Considerations

### 1. İç Sınıf (Inner Class) vs Ayrı Dosya Stratejisi
- **Seçilen Yaklaşım:** Inner class kullanımı
- **Avantajlar:**
  - Dosya sayısı artmaz (kullanıcının isteği)
  - İlgili algoritma ana sınıfla birlikte yaşar
  - Encapsulation ve cohesion artar
  - Test coverage ana sınıf üzerinden hesaplanır
- **Dezavantajlar:**
  - Büyük sınıflar oluşabilir (PasswordManager ~1000+ satır olabilir)
  - Code reusability azalabilir
- **Öneri:** Inner class kullan, ama her algoritma için iyi dokümantasyon yap

### 2. Test Stratejisi
- **TDD değil, Implementation-First Approach:**
  - Önce algoritmayı mevcut sınıfa ekle
  - Algoritmayı çalışır hale getir
  - Sonra testleri yaz
  - Coverage'ı %90+ çıkar
- **Test Organizasyonu:**
  - Her ana sınıf için tek test dosyası (örn: PasswordManagerTest.java)
  - İç sınıflar için ayrı test metodları (@Test testDoublyLinkedList(), @Test testCustomHashTable())
  - Private metodları test etmek için reflection KULLANMA, public interface'den test et
- **Öneri:** Implementation-first, sonra comprehensive test yazma

### 3. Code Organization ve Readability
- **Dosya Büyüklüğü Yönetimi:**
  - PasswordManager.java ~1500 satır olabilir (acceptable for Java)
  - İyi bölümleme: region comments kullan
  ```java
  // ========== CREDENTIALS STORAGE ==========
  private final CustomHashTable<String, String> credentials;
  
  // ========== ACCESS PATTERN TRACKING ==========
  private AccessMatrix accessMatrix;
  
  // ========== UNDO/REDO OPERATIONS ==========
  private CommandStack undoStack;
  ```
- **Öneri:** Region comments ve logical grouping ile okunabilirliği artır

### 4. Backward Compatibility
- **Mevcut API'leri Bozmama:**
  - `Map<String, String> credentials` → `CustomHashTable<String, String> credentials` değişimi
  - CustomHashTable, Map interface implement ederse geriye uyumlu kalır
  - Alternatif: CustomHashTable'ı internal olarak kullan ama dış API'yi değiştirme
- **Öneri:** İç implementasyonu değiştir ama public API'yi koru

### 5. Performance Implications
- **Algoritma Seçimi:**
  - DoublyLinkedList: O(n) access ama O(1) insert/delete at ends
  - XOR Linked List: Memory efficient ama traversal complexity
  - Custom Hash Table: O(1) average, ama collision handling
  - Heap Sort: O(n log n) guaranteed
  - KMP: O(n + m) pattern matching
- **Öneri:** Performans critical değil, algoritma gösterimi amaçlı

### 6. Documentation Standards
- **Doxygen Comments:**
  - Her inner class için @brief ve @details
  - Her public method için @param, @return, @throws
  - Algoritma complexity'si dokümante et (Big-O notation)
  ```java
  /**
   * @brief Searches for a pattern in text using KMP algorithm
   * @details Time complexity: O(n + m) where n is text length, m is pattern length
   * @param text The text to search in
   * @param pattern The pattern to search for
   * @return Index of first occurrence, or -1 if not found
   */
  ```
- **Öneri:** Comprehensive Doxygen documentation ile code quality artır

## Yeni Plan Özeti

**Toplam 12 Step:**
1. Step 1: Baseline ve analiz
2. Step 2: Password.java - DoublyLinkedList (history)
3. Step 3: PasswordManager.java - Sparse Matrix (access patterns)
4. Step 4: PasswordManager.java - Stack (undo/redo)
5. Step 5: PasswordManager.java - Custom Hash Table
6. Step 6: PasswordManager.java - Heap Sort (ranking)
7. Step 7: PasswordGenerator.java - KMP (pattern matching)
8. Step 8: FilePasswordStorage.java - XOR Linked List
9. Step 9: FilePasswordStorage.java - Huffman Coding
10. Step 10: PasswordManager.java - Graph (BFS/DFS/SCC)
11. Step 11: PasswordManager.java - Queue (scheduled changes)
12. Step 12: Test coverage enhancement (%90+) ve final validation

**Her Step:**
- Önce algorithm implementation (inner class veya private method)
- Public interface metodları ekle
- Comprehensive tests yaz (mevcut test dosyasına ekle)
- Coverage kontrol et
- Doxygen comments ekle
- Build & test (`mvn clean test`)

**Kritik Fark:**
- ❌ Yeni klasörler ve dosyalar oluşturmuyoruz
- ✅ Mevcut sınıflara inner class olarak ekliyoruz
- ❌ TDD approach (test-first) kullanmıyoruz
- ✅ Implementation-first, sonra test yazıyoruz
- ❌ Test utility dosyaları oluşturmuyoruz (gerekmedikçe)
- ✅ Mevcut test dosyalarını genişletiyoruz

## Current Project Status (Updated - Integration Approach)

### Maven Configuration
- **Dependencies:** SQLite JDBC, JUnit 4.11, Hamcrest, SLF4J, Logback, System Lambda, MigLayout, Mockito, PowerMock
- **Plugins:** maven-compiler-plugin (Java 17), maven-surefire-plugin, jacoco-maven-plugin (80% line, 50% branch), maven-site-plugin, maven-shade-plugin, launch4j-maven-plugin

### Current Coverage Baseline
| Class | Coverage | Target | Algoritma Entegrasyonu |
|-------|----------|--------|----------------------|
| Password | 100% | 100% | + DoublyLinkedList (history) |
| PasswordManager | 53% | 95%+ | + Sparse Matrix, Stack, Queue, Heap, CustomHashTable, Graph |
| PasswordGenerator | 98.5% | 100% | + KMP String Matching |
| FilePasswordStorage | 94.6% | 100% | + XOR Linked List, Huffman Coding |
| DatabasePasswordStorage | 27.6% | 90%+ | Test enhancement only |
| AuthManager | 49.4% | 90%+ | Test enhancement only |
| PasswordApp | 55.8% | 90%+ | Test enhancement only |
| PlatformManager | 72.1% | 90%+ | Test enhancement only |
| EncryptionUtil | 87.5% | 95%+ | Test enhancement only |
| AutoLoginManager | 78.9% | 90%+ | Test enhancement only |
| StorageType | 100% | 100% | No change |
| PasswordStorageFactory | 68.2% | 90%+ | Test enhancement only |

**Overall Coverage Target: 63% → 90%+**

### Algoritma Dağılımı (Sınıflara Göre)

#### Password.java (1 algoritma)
- ✅ DoublyLinkedList - Inner class `PasswordHistory`

#### PasswordManager.java (7 algoritma - EN BÜYÜK SINIF)
- ✅ Sparse Matrix - Inner class `AccessMatrix`
- ✅ Stack - Inner class `CommandStack` (Undo/Redo)
- ✅ Queue - Inner class `ChangeQueue` (Scheduled changes)
- ✅ Heap Sort - Private methods `heapSort()`, `heapify()`
- ✅ Custom Hash Table - Inner class `CustomHashTable<K,V>` (replaces HashMap)
- ✅ Graph (BFS/DFS) - Inner class `ServiceGraph`
- ✅ SCC - Method in `ServiceGraph` (Tarjan's algorithm)

#### PasswordGenerator.java (1 algoritma)
- ✅ KMP String Matching - Static methods `kmpSearch()`, `computeLPSArray()`

#### FilePasswordStorage.java (2 algoritma)
- ✅ XOR Linked List - Inner class `XORLinkedStorage`
- ✅ Huffman Coding - Inner class `HuffmanCompressor`

**Toplam: 11 algoritma / 4 ana sınıf**

### Package Structure (DEĞIŞMEYECEK - No New Packages)
```
com.ucoruh.password/
├── Password.java (+ PasswordHistory inner class) ← DoublyLinkedList
├── PasswordManager.java (+ 7 inner classes) ← Çoğu algoritma
├── PasswordGenerator.java (+ KMP methods) ← String matching
├── FilePasswordStorage.java (+ 2 inner classes) ← Compression
├── DatabasePasswordStorage.java (no change) ← Sadece test
├── AuthManager.java (no change) ← Sadece test
├── PasswordApp.java (no change) ← Sadece test
├── EncryptionUtil.java (no change) ← Sadece test
├── AutoLoginManager.java (no change) ← Sadece test
├── PlatformManager.java (no change) ← Sadece test
├── PasswordStorageFactory.java (no change) ← Sadece test
├── StorageType.java (no change)
├── InterfacePasswordStorage.java (no change)
└── gui/ (no changes) ← Sadece test enhancement
    ├── PasswordManagerGUI.java
    ├── DialogController.java
    ├── AddPasswordController.java
    ├── ViewPasswordController.java
    ├── UpdatePasswordController.java
    ├── DeletePasswordController.java
    └── GeneratePasswordController.java
```

### Design Patterns in Use
- **Singleton:** AuthManager
- **Factory:** PasswordStorageFactory
- **Strategy:** InterfacePasswordStorage implementations
- **Command:** (YENİ) CommandStack in PasswordManager
- **MVC:** GUI controllers

### Implementation Complexity Estimate

| Sınıf | Mevcut Satır | Eklenecek Satır | Tahmini Toplam |
|-------|--------------|-----------------|----------------|
| Password.java | ~100 | +150 (DoublyLinkedList) | ~250 |
| PasswordManager.java | ~253 | +800 (7 algoritma) | ~1050 |
| PasswordGenerator.java | ~144 | +100 (KMP) | ~244 |
| FilePasswordStorage.java | ~223 | +250 (XOR + Huffman) | ~473 |

**Toplam Yeni Kod: ~1300 satır**

## Next Steps

**Ready to start with Step 1?** 
- Mevcut testleri çalıştır ve baseline oluştur
- Her algoritmanın hangi sınıfa ekleneceğini doğrula
- Implementation-first approach ile algoritmaları ekle
- Her adımda comprehensive test yaz
- %90+ coverage hedefine ulaş

**Kritik Farklar:**
- ❌ Yeni dosya/klasör oluşturma
- ✅ Mevcut sınıflara inner class ekle
- ❌ Test-first (TDD)
- ✅ Implementation-first, sonra test
- ✅ Incremental approach (step-by-step validation)
