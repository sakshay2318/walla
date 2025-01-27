import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

public class RoleBasedAccessControlScanner {

    // Define RBAC patterns
    private static final List<Pattern> rbacPatterns = Arrays.asList(
        Pattern.compile("\\bif\\s*\\(\\s*user\\.role\\s*===\\s*['\"].+['\"]\\s*\\)"), // Example: if (user.role === 'admin')
        Pattern.compile("\\bif\\s*\\(\\s*user\\.roles\\s*\\.includes\\(\\s*['\"].+['\"]\\s*\\)\\s*\\)"), // Example: if (user.roles.includes('editor'))
        Pattern.compile("\\buser\\.permissions\\s*\\.includes\\(\\s*['\"].+['\"]\\s*\\)"), // Example: user.permissions.includes('read')
        Pattern.compile("\\brequireRole\\(['\"].+['\"]\\)"), // Example: requireRole('admin')
        Pattern.compile("\\brequirePermission\\(['\"].+['\"]\\)"), // Example: requirePermission('edit')
        Pattern.compile("\\bcheckAccess\\(['\"].+['\"],\\s*user\\)"), // Example: checkAccess('resource', user)
        Pattern.compile("\\buser\\.hasRole\\(['\"].+['\"]\\)"), // Example: user.hasRole('manager')
        Pattern.compile("\\buser\\.hasPermission\\(['\"].+['\"]\\)"), // Example: user.hasPermission('delete')
        Pattern.compile("\\bif\\s*\\(\\s*hasRole\\(['\"].+['\"]\\)\\s*\\)"), // Example: if (hasRole('viewer'))
        Pattern.compile("\\bif\\s*\\(\\s*hasPermission\\(['\"].+['\"]\\)\\s*\\)"), // Example: if (hasPermission('create'))
        Pattern.compile("\\broleCheck\\(['\"].+['\"]\\)"), // Example: roleCheck('owner')
        Pattern.compile("\\bpermissionCheck\\(['\"].+['\"]\\)") // Example: permissionCheck('editResource')
    );

    // Method to scan a single file
    private static List<Map<String, Object>> scanFile(String filePath) throws IOException {
        String content = Files.readString(Path.of(filePath));
        System.out.println("Scanning file: " + filePath);

        List<Map<String, Object>> findings = new ArrayList<>();
        for (int i = 0; i < rbacPatterns.size(); i++) {
            Matcher matcher = rbacPatterns.get(i).matcher(content);
            while (matcher.find()) {
                int lineNumber = content.substring(0, matcher.start()).split("\n").length;
                Map<String, Object> finding = new HashMap<>();
                finding.put("patternIndex", i + 1);
                finding.put("match", matcher.group());
                finding.put("line", lineNumber);
                findings.add(finding);
            }
        }
        return findings;
    }

    // Method to scan the project directory
    private static void scanProject(String directory) throws IOException {
        System.out.println("Scanning project for Role-Based Access Control vulnerabilities in " + directory);

        List<Path> files = Files.walk(Paths.get(directory))
                .filter(path -> path.toString().endsWith(".js") || path.toString().endsWith(".jsx"))
                .collect(Collectors.toList());

        List<Map<String, Object>> results = new ArrayList<>();
        for (Path file : files) {
            String relativePath = Paths.get(directory).relativize(file).toString();
            System.out.println("Checking file: " + relativePath);
            List<Map<String, Object>> findings = scanFile(file.toString());
            if (!findings.isEmpty()) {
                Map<String, Object> result = new HashMap<>();
                result.put("file", relativePath);
                result.put("findings", findings);
                results.add(result);
            }
        }

        // Print results
        if (!results.isEmpty()) {
            System.out.println("\nPotential RBAC vulnerabilities found:\n");
            for (Map<String, Object> result : results) {
                System.out.println("File: " + result.get("file"));
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> findings = (List<Map<String, Object>>) result.get("findings");
                for (Map<String, Object> finding : findings) {
                    System.out.printf("Pattern #%d: %s (Line: %d)\n",
                            finding.get("patternIndex"), finding.get("match"), finding.get("line"));
                }
            }
        } else {
            System.out.println("No RBAC vulnerabilities detected!");
        }
    }

    public static void main(String[] args) {
        try {
            String projectDir = System.getProperty("user.dir");
            scanProject(projectDir);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
