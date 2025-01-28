import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

public class MainScanner {

    // Patterns for detecting vulnerabilities
    private static final String IDOR_PATTERN = "\\.params\\.id"; // Example: req.params.id
    private static final String RBAC_PATTERN = "req\\.user\\.role"; // Example: Role-based checks like req.user.role === 'admin'
    private static final String AUTHENTICATE_PATTERN = "authenticate"; // Example: Middleware authenticate

    public static void main(String[] args) throws IOException {
        // Directory to scan
        String directory = "/Users/a0s114t/Desktop/ASCSD1";
        scanProject(directory);
    }

    // Scan the project to gather .js and .jsx files
    public static void scanProject(String directory) throws IOException {
        System.out.println("Scanning project for vulnerabilities in " + directory + "\n");

        List<Path> files;
        try {
            files = Files.walk(Paths.get(directory))
                    .filter(path -> path.toString().endsWith(".js") || path.toString().endsWith(".jsx"))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            System.out.println("No JavaScript code found!");
            throw new RuntimeException(e);
        }

        for (Path file : files) {
            String relativePath = Paths.get(directory).relativize(file).toString();
            System.out.println("Checking file: " + relativePath);
            scanFile(file.toString());
        }
    }

    // Method to scan a single file
    public static void scanFile(String filePath) throws IOException {
        System.out.println("Scanning file: " + filePath);

        List<Map<String, Object>> findings = new ArrayList<>();
        List<String> fileLines = Files.readAllLines(Paths.get(filePath));

        boolean hasRBAC = false;
        boolean hasAuthenticate = false;

        // First pass: Check for RBAC and authentication patterns in the file
        for (String line : fileLines) {
            if (line.matches(".*" + RBAC_PATTERN + ".*")) {
                hasRBAC = true;
            }
            if (line.matches(".*" + AUTHENTICATE_PATTERN + ".*")) {
                hasAuthenticate = true;
            }
        }

        // Second pass: Identify IDOR patterns and relate them to RBAC or authenticate patterns
        for (int i = 0; i < fileLines.size(); i++) {
            String line = fileLines.get(i);
            if (line.matches(".*" + IDOR_PATTERN + ".*")) {
                Map<String, Object> finding = new HashMap<>();
                finding.put("patternIndex", 5); // Pattern #5 for IDOR
                finding.put("match", line.trim());
                finding.put("line", i + 1);
                finding.put("description", "Check the IDOR vulnerability and rectify the security issue!");

                // Relate to RBAC or authentication
                if (hasRBAC || hasAuthenticate) {
                    finding.put("status", "Not Vulnerable (Mitigated by RBAC or Authentication)");
                } else {
                    finding.put("status", "Vulnerable (No RBAC or Authentication found)");
                }

                findings.add(finding);
            }
        }

        // Print findings
        if (!findings.isEmpty()) {
            System.out.println("File: " + filePath);
            for (Map<String, Object> finding : findings) {
                System.out.printf(
                        "Pattern #%d: %s (Line: %d)\nDescription: %s\nStatus: %s\n\n",
                        finding.get("patternIndex"),
                        finding.get("match"),
                        finding.get("line"),
                        finding.get("description"),
                        finding.get("status")
                );
            }
        }
    }
}
