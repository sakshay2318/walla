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
import java.util.ArrayList;
import java.util.regex.Pattern;

public class RBACPatterns {
    public static void main(String[] args) {
        // Hardcoded list of regex patterns to detect missing RBAC in .js and .jsx files
        ArrayList<Pattern> rbacPatterns = new ArrayList<>();

        // 1. No role check in API endpoint
        rbacPatterns.add(Pattern.compile("\\bapp\\.(get|post|put|delete)\\s*\\(.*\\)\\s*=>\\s*\\{[^}]*\\}")); // No role validation in route
        // 2. Exposed sensitive routes
        rbacPatterns.add(Pattern.compile("/admin|/settings|/user-management")); // Sensitive routes with no RBAC
        // 3. Hardcoded role-based tokens
        rbacPatterns.add(Pattern.compile("\\bif\\s*\\(\\s*req\\.headers\\['authorization'\\]\\s*==\\s*'Bearer.*'\\s*\\)")); // Hardcoded token
        // 4. Missing role validation for actions
        rbacPatterns.add(Pattern.compile("\\buserId\\s*:\\s*\\w+\\s*,")); // Actions referencing userId without validation
        // 5. No middleware for RBAC enforcement
        rbacPatterns.add(Pattern.compile("\\b(app\\.use|router\\.use)\\(.*auth.*\\)")); // Check if auth middleware is missing
        // 6. Role not validated before accessing resources
        rbacPatterns.add(Pattern.compile("\\bfetch\\s*\\(.*\\)\\s*\\.then\\(.*\\)")); // Fetch calls without role checks
        // 7. Direct DB query without validation
        rbacPatterns.add(Pattern.compile("\\bdb\\.(query|find|insert|delete)\\s*\\(.*\\)")); // DB operations without RBAC
        // 8. Directly rendering admin panels
        rbacPatterns.add(Pattern.compile("<AdminPanel\\s*>")); // AdminPanel rendered without RBAC
        // 9. Missing conditional rendering
        rbacPatterns.add(Pattern.compile("\\b(user|isAdmin)\\s*\\?\\s*.*\\:")); // Conditional role-based rendering missing
        // 10. Missing role-based API checks
        rbacPatterns.add(Pattern.compile("\\brouter\\.(get|post|put|delete)\\s*\\(.*\\)")); // Routes without role validation

        // 11. Improper role check
        rbacPatterns.add(Pattern.compile("\\brole\\s*==\\s*['\"](admin|user)['\"]")); // Hardcoded single role checks
        // 12. Authorization header check only
        rbacPatterns.add(Pattern.compile("\\breq\\.headers\\['authorization'\\]")); // Only authorization header checked
        // 13. Client-side sensitive action rendering
        rbacPatterns.add(Pattern.compile("<button.*onClick=.*>Delete</button>")); // Delete button rendered without role validation
        // 14. Missing role validation on sensitive links
        rbacPatterns.add(Pattern.compile("<a\\s*href=['\"].*(admin|settings)['\"]>.*</a>")); // Links to sensitive pages
        // 15. Using `req.query` directly
        rbacPatterns.add(Pattern.compile("\\breq\\.query\\.\\w+")); // Direct use of query parameters without validation
        // 16. Using `req.body` directly
        rbacPatterns.add(Pattern.compile("\\breq\\.body\\.\\w+")); // Direct use of body parameters without validation
        // 17. Direct rendering of sensitive data
        rbacPatterns.add(Pattern.compile("\\b(res\\.send|res\\.json)\\s*\\(.*\\)")); // Sending sensitive data without checks
        // 18. Direct database operations in endpoints
        rbacPatterns.add(Pattern.compile("\\bdb\\.\\w+\\s*\\(.*\\)")); // DB calls in routes without role checks
        // 19. Admin keyword in strings
        rbacPatterns.add(Pattern.compile("['\"].*(admin).*['\"]")); // Hardcoded admin references
        // 20. Exposing sensitive environment variables
        rbacPatterns.add(Pattern.compile("process\\.env\\.(ADMIN|SUPERUSER|ROOT)")); // Exposing sensitive env variables

        // 21. Role validation missing in Redux actions
        rbacPatterns.add(Pattern.compile("\\bdispatch\\(.*\\)")); // Dispatch actions without role checks
        // 22. Missing RBAC in GraphQL resolvers
        rbacPatterns.add(Pattern.compile("\\b(resolvers|resolver)\\s*\\{")); // Resolvers defined without role checks
        // 23. Hardcoded sensitive data in JSX
        rbacPatterns.add(Pattern.compile("defaultProps\\s*=\\s*\\{.*role:.*['\"].*admin.*['\"].*\\}")); // Hardcoded admin role in props
        // 24. Missing role-based checks in REST APIs
        rbacPatterns.add(Pattern.compile("\\baxios\\s*\\.get\\s*\\(.*\\)")); // REST calls without role checks
        // 25. Use of wildcard imports
        rbacPatterns.add(Pattern.compile("\\bimport\\s*\\*\\s*as\\s*\\w+\\s*from")); // Wildcard imports with no specific control
        // 26. Sensitive page links without validation
        rbacPatterns.add(Pattern.compile("\\b<Link\\s*to=['\"].*(admin|settings).*['\"]\\s*>")); // Links rendered without validation
        // 27. Admin actions in onclick handlers
        rbacPatterns.add(Pattern.compile("\\bonClick\\s*=\\s*\\{.*delete.*\\}")); // Delete action in onclick without role checks
        // 28. JWT token decoding without validation
        rbacPatterns.add(Pattern.compile("\\bjsonwebtoken\\.decode\\s*\\(.*\\)")); // Decoding JWTs without validating roles
        // 29. Admin keywords in comments
        rbacPatterns.add(Pattern.compile("//.*admin.*")); // Admin roles referenced in comments
        // 30. Missing server-side RBAC
        rbacPatterns.add(Pattern.compile("\\b(req|res)\\.(params|body|query)\\.(role|permission)\\b")); // Missing server-side RBAC logic

        // Print all patterns for verification
        rbacPatterns.forEach(System.out::println);
    }
}
import java.util.ArrayList;
import java.util.regex.Pattern;

public class AdvertisingWebsitePatterns {
    public static void main(String[] args) {
        // Hardcoded list of regex patterns for advertising websites
        ArrayList<Pattern> advertisingPatterns = new ArrayList<>();

        // 1. Direct rendering of advertisements
        advertisingPatterns.add(Pattern.compile("<AdComponent\\s*.*>")); // Rendering ads without validation
        // 2. Insecure API keys exposed
        advertisingPatterns.add(Pattern.compile("(apiKey|adKey)\\s*[:=]\\s*['\"].+['\"]")); // Exposing ad API keys
        // 3. Unvalidated ad click tracking
        advertisingPatterns.add(Pattern.compile("\\btrackClick\\(.*\\)")); // Ad click tracking without validation
        // 4. No validation for ad content
        advertisingPatterns.add(Pattern.compile("<AdContent\\s*>")); // Rendering ad content without validation
        // 5. Missing rate limiting for ad requests
        advertisingPatterns.add(Pattern.compile("\\baxios\\.get\\(.*\\/ads.*\\)")); // No rate limiting for ad fetch
        // 6. Unrestricted ad placement scripts
        advertisingPatterns.add(Pattern.compile("\\b<script\\s*src=['\"].*adsense.*['\"]>")); // AdSense scripts unrestricted
        // 7. Direct insertion of ad URLs
        advertisingPatterns.add(Pattern.compile("\\b(adUrl|bannerUrl)\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded ad URLs
        // 8. Missing ad visibility checks
        advertisingPatterns.add(Pattern.compile("\\b(adVisible|isAdVisible)\\s*[:=]\\s*\\w+")); // Visibility checks missing
        // 9. Hardcoded ad targeting
        advertisingPatterns.add(Pattern.compile("\\btargetAudience\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded targeting
        // 10. No validation for ad metrics
        advertisingPatterns.add(Pattern.compile("\\b(adClicks|adImpressions|adRevenue)\\s*[:=]\\s*\\w+")); // Metrics unvalidated

        // 11. Ad scripts injected via query params
        advertisingPatterns.add(Pattern.compile("\\bwindow\\.location\\.search\\s*.*=.*adScript")); // Ad script injection
        // 12. Sensitive ad keywords exposed
        advertisingPatterns.add(Pattern.compile("\\b(keyword|adTag)\\s*[:=]\\s*['\"].+['\"]")); // Exposed keywords
        // 13. Unvalidated ad parameters in requests
        advertisingPatterns.add(Pattern.compile("\\b(req\\.query|req\\.body)\\.(adId|adType)")); // Unvalidated ad parameters
        // 14. Hardcoded ad placements
        advertisingPatterns.add(Pattern.compile("\\b(adPlacement|bannerPlacement)\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded placements
        // 15. Inline ad scripts
        advertisingPatterns.add(Pattern.compile("<script>.*ad\\s*=.*</script>")); // Inline ad scripts
        // 16. Missing input sanitization for ads
        advertisingPatterns.add(Pattern.compile("\\b(req\\.body|req\\.query)\\.(adText|adLink)")); // Unvalidated inputs
        // 17. Hardcoded ad categories
        advertisingPatterns.add(Pattern.compile("\\b(adCategory|adType)\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded categories
        // 18. Unrestricted third-party ad scripts
        advertisingPatterns.add(Pattern.compile("<script\\s*src=['\"].*(doubleclick|ads).*['\"]>")); // Third-party ad scripts
        // 19. Ad serving via insecure HTTP
        advertisingPatterns.add(Pattern.compile("http://.*\\/ads")); // Insecure ad serving
        // 20. Ad tracking cookies set without consent
        advertisingPatterns.add(Pattern.compile("\\bdocument\\.cookie\\s*.*=.*adTracker")); // Ad cookies without consent

        // 21. Missing CORS checks for ad APIs
        advertisingPatterns.add(Pattern.compile("\\b(res\\.setHeader\\s*.*Access-Control-Allow-Origin)")); // Missing CORS
        // 22. Direct rendering of ad HTML
        advertisingPatterns.add(Pattern.compile("\\binnerHTML\\s*=\\s*['\"].*<ad>.*['\"]")); // Unsafe ad rendering
        // 23. No validation for ad analytics
        advertisingPatterns.add(Pattern.compile("\\b(adAnalytics|trackAdPerformance)\\s*\\(")); // Analytics unvalidated
        // 24. Exposed ad payment info
        advertisingPatterns.add(Pattern.compile("\\b(adPayment|adBilling)\\s*[:=]\\s*['\"].+['\"]")); // Payment data exposed
        // 25. Missing role checks for ad creation
        advertisingPatterns.add(Pattern.compile("\\bcreateAd\\s*\\(")); // Ad creation without role validation
        // 26. Unvalidated ad size parameters
        advertisingPatterns.add(Pattern.compile("\\b(adWidth|adHeight)\\s*[:=]\\s*\\d+")); // Size unvalidated
        // 27. Inline styles for ads
        advertisingPatterns.add(Pattern.compile("<div\\s*style=['\"].*ad.*['\"]>")); // Inline styles for ads
        // 28. Ad tracking via unsecure params
        advertisingPatterns.add(Pattern.compile("\\b(adTrack|trackAd)\\s*[:=]\\s*\\w+")); // Tracking via insecure methods
        // 29. Hardcoded ad campaign names
        advertisingPatterns.add(Pattern.compile("\\b(campaignName|adCampaign)\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded campaign names
        // 30. Direct rendering of ad banners
        advertisingPatterns.add(Pattern.compile("<BannerAd\\s*>")); // Rendering banner ads without validation

        // 31. Missing validation for ad click events
        advertisingPatterns.add(Pattern.compile("\\b(onAdClick|handleClick)\\s*\\(")); // Click event handlers unvalidated
        // 32. Unrestricted ad partner access
        advertisingPatterns.add(Pattern.compile("\\b(adPartner|partnerId)\\s*[:=]\\s*['\"].+['\"]")); // Partner ID exposed
        // 33. Hardcoded ad budgets
        advertisingPatterns.add(Pattern.compile("\\b(adBudget|budget)\\s*[:=]\\s*\\d+")); // Hardcoded budget values
        // 34. Unencrypted ad requests
        advertisingPatterns.add(Pattern.compile("http://.*\\?adId=")); // Ad requests over HTTP
        // 35. Ad script injection via user input
        advertisingPatterns.add(Pattern.compile("\\b(req\\.body|req\\.query)\\.(script|adScript)")); // Script injection
        // 36. Missing security headers for ads
        advertisingPatterns.add(Pattern.compile("\\b(res\\.setHeader\\s*.*X-Content-Type-Options)")); // Missing headers
        // 37. Unvalidated ad targeting conditions
        advertisingPatterns.add(Pattern.compile("\\b(targeting|targetAudience)\\s*\\(")); // Unvalidated targeting
        // 38. Ad revenue calculation without validation
        advertisingPatterns.add(Pattern.compile("\\b(adRevenue|calculateRevenue)\\s*\\(")); // Revenue calculation unvalidated
        // 39. Inline JSON for ads
        advertisingPatterns.add(Pattern.compile("\\bJSON\\.stringify\\(.*ad.*\\)")); // Inline JSON with ads
        // 40. Missing validations for ad deletion
        advertisingPatterns.add(Pattern.compile("\\bdeleteAd\\s*\\(")); // Deletion without role checks

        // 41. Exposed ad preview URLs
        advertisingPatterns.add(Pattern.compile("\\b(adPreview|previewUrl)\\s*[:=]\\s*['\"].+['\"]")); // Exposed preview URLs
        // 42. Missing ad visibility tracking
        advertisingPatterns.add(Pattern.compile("\\btrackVisibility\\s*\\(")); // Visibility tracking missing
        // 43. Ad rendering via untrusted sources
        advertisingPatterns.add(Pattern.compile("<script\\s*src=['\"].*ad.*['\"]>")); // Ad scripts from untrusted sources
        // 44. Hardcoded ad platform credentials
        advertisingPatterns.add(Pattern.compile("\\b(adPlatform|adManager)\\s*[:=]\\s*['\"].+['\"]")); // Exposed platform credentials
        // 45. Missing input sanitization for ad forms
        advertisingPatterns.add(Pattern.compile("\\b(input|textarea).*ad.*")); // Ad forms without sanitization
        // 46. Unvalidated ad campaign durations
        advertisingPatterns.add(Pattern.compile("\\b(campaignDuration|adDuration)\\s*[:=]\\s*\\d+")); // Duration unvalidated
        // 47. Missing logging for ad actions
        advertisingPatterns.add(Pattern.compile("\\b(logAdAction|trackAdEvent)\\s*\\(")); // Ad actions unlogged
        // 48. Exposed ad partner APIs
        advertisingPatterns.add(Pattern.compile("\\b(adPartnerApi|partnerApiUrl)\\s*[:=]\\s*['\"].+['\"]")); // Exposed APIs
        // 49. Hardcoded ad placement logic
        advertisingPatterns.add(Pattern.compile("\\b(adPosition|adSlot)\\s*[:=]\\s*['\"].+['\"]")); // Hardcoded placements
        // 50. Ad components rendered without RBAC
        advertisingPatterns.add(Pattern.compile("<AdManager\\s*>")); // AdManager rendered without checks

        // Print all patterns for verification
        advertisingPatterns.forEach(System.out::println);
    }
}
import java.util.ArrayList;
import java.util.regex.Pattern;

public class RBACPatterns {
    public static void main(String[] args) {
        // Hardcoded list of regex patterns for detecting missing RBAC checks
        ArrayList<Pattern> rbacPatterns = new ArrayList<>();

        // 1. Direct API access without user role checks
        rbacPatterns.add(Pattern.compile("\\baxios\\.get\\(.*\\)")); // Unrestricted API call
        // 2. Missing `req.user.role` validation
        rbacPatterns.add(Pattern.compile("req\\.user\\.(?!role)")); // User object accessed without role check
        // 3. Missing middleware for RBAC
        rbacPatterns.add(Pattern.compile("\\bapp\\.get\\(.*\\)")); // Express route without middleware
        // 4. Unvalidated role in permissions
        rbacPatterns.add(Pattern.compile("\\bif\\s*\\(.*role.*\\)")); // Role checks without strict validation
        // 5. Hardcoded admin access
        rbacPatterns.add(Pattern.compile("role\\s*==\\s*['\"]admin['\"]")); // Hardcoded role check
        // 6. Missing checks for `req.user`
        rbacPatterns.add(Pattern.compile("req\\.user\\.\\w+")); // User object used without verification
        // 7. No RBAC check before database query
        rbacPatterns.add(Pattern.compile("\\b(User|Admin|Role)\\.find")); // Direct DB queries without authorization
        // 8. Missing checks for sensitive endpoints
        rbacPatterns.add(Pattern.compile("\\b(app|router)\\.(get|post|put|delete)\\(.*\\)")); // Routes without middleware
        // 9. Missing `isAdmin` check
        rbacPatterns.add(Pattern.compile("isAdmin\\s*[:=]\\s*false")); // Flag hardcoded without validation
        // 10. No role validation in conditional statements
        rbacPatterns.add(Pattern.compile("\\bif\\s*\\(.*\\)\\s*\\{\\s*return")); // Conditions without role checks

        // 11. Unvalidated `req.params` access
        rbacPatterns.add(Pattern.compile("req\\.params\\.(?!id|userId)\\w+")); // Params used without validation
        // 12. Role used in insecure string comparisons
        rbacPatterns.add(Pattern.compile("role\\s*===\\s*['\"]\\w+['\"]")); // Role checks with insecure comparisons
        // 13. Unvalidated `req.headers` usage
        rbacPatterns.add(Pattern.compile("req\\.headers\\.(?!authorization)\\w+")); // Headers used without validation
        // 14. Missing RBAC check in fetch
        rbacPatterns.add(Pattern.compile("\\bfetch\\(.*\\)")); // Unrestricted API fetch
        // 15. No role validation for POST requests
        rbacPatterns.add(Pattern.compile("app\\.post\\(.*\\)")); // POST endpoint without middleware
        // 16. Missing validation for role in GraphQL resolvers
        rbacPatterns.add(Pattern.compile("resolve\\s*:\\s*\\(.*\\)")); // GraphQL resolver without role validation
        // 17. Unvalidated query parameters in RBAC
        rbacPatterns.add(Pattern.compile("req\\.query\\.(?!role)\\w+")); // Query params used without validation
        // 18. Missing role-based redirects
        rbacPatterns.add(Pattern.compile("res\\.redirect\\(.*\\)")); // Redirects without role validation
        // 19. Direct admin actions without checks
        rbacPatterns.add(Pattern.compile("admin\\.(?!roleCheck)\\w+")); // Admin actions without checks
        // 20. Unchecked `localStorage` role access
        rbacPatterns.add(Pattern.compile("localStorage\\.getItem\\(['\"]role['\"]\\)")); // Role from localStorage without validation

        // 21. Missing RBAC in WebSocket events
        rbacPatterns.add(Pattern.compile("socket\\.on\\(.*\\)")); // Socket events without role validation
        // 22. No role checks in job schedulers
        rbacPatterns.add(Pattern.compile("\\bcron\\.schedule\\(.*\\)")); // Scheduled jobs without role checks
        // 23. Missing role validation in file uploads
        rbacPatterns.add(Pattern.compile("multer\\(.*\\)")); // File upload without role checks
        // 24. Missing role validation in PUT requests
        rbacPatterns.add(Pattern.compile("app\\.put\\(.*\\)")); // PUT endpoint without middleware
        // 25. Unvalidated user actions in frontend components
        rbacPatterns.add(Pattern.compile("\\bonClick\\s*=\\s*\\{.*\\}")); // Click events without validation
        // 26. Role passed via insecure URL parameters
        rbacPatterns.add(Pattern.compile("role=\\w+")); // Role passed via URL
        // 27. Missing RBAC in DELETE requests
        rbacPatterns.add(Pattern.compile("app\\.delete\\(.*\\)")); // DELETE endpoint without middleware
        // 28. Unvalidated role in token payload
        rbacPatterns.add(Pattern.compile("jwt\\.decode\\(.*\\)")); // JWT decoded without role validation
        // 29. Missing role validation in server-side rendering
        rbacPatterns.add(Pattern.compile("getServerSideProps\\s*\\(.*\\)")); // Server-side props without validation
        // 30. Unrestricted API routes in Next.js
        rbacPatterns.add(Pattern.compile("export\\s+default\\s+function\\s+handler")); // Next.js API handler without checks

        // 31. No role validation in admin dashboards
        rbacPatterns.add(Pattern.compile("<AdminDashboard\\s*>")); // Admin component rendered without checks
        // 32. Unvalidated role in useEffect
        rbacPatterns.add(Pattern.compile("useEffect\\(.*role")); // Role checked improperly in useEffect
        // 33. Missing RBAC in socket emit events
        rbacPatterns.add(Pattern.compile("socket\\.emit\\(.*\\)")); // Emit events without role validation
        // 34. Unvalidated actions in Redux reducers
        rbacPatterns.add(Pattern.compile("state\\.(?!role)\\w+")); // Reducers without role validation
        // 35. Missing RBAC in frontend routes
        rbacPatterns.add(Pattern.compile("<Route\\s+path=")); // Frontend route without RBAC
        // 36. Direct admin database queries
        rbacPatterns.add(Pattern.compile("\\bdb\\.admin\\.(?!validate)\\w+")); // Admin queries without validation
        // 37. No role validation for external APIs
        rbacPatterns.add(Pattern.compile("axios\\.post\\(.*external.*\\)")); // External APIs without RBAC
        // 38. Missing validation in search queries
        rbacPatterns.add(Pattern.compile("\\bsearch\\(.*\\)")); // Search queries without role validation
        // 39. Unrestricted file downloads
        rbacPatterns.add(Pattern.compile("\\bdownload\\s*\\(.*\\)")); // File download without role checks
        // 40. Unvalidated user roles in logs
        rbacPatterns.add(Pattern.compile("\\bconsole\\.log\\(.*role.*\\)")); // Logging roles without validation

        // 41. No RBAC in real-time updates
        rbacPatterns.add(Pattern.compile("update\\s*\\(.*\\)")); // Real-time updates without role checks
        // 42. Unvalidated user permissions in frontend
        rbacPatterns.add(Pattern.compile("\\bhasPermission\\s*\\(.*\\)")); // Permissions improperly validated
        // 43. Missing validation in file processing
        rbacPatterns.add(Pattern.compile("fs\\.readFile\\(.*\\)")); // File processing without role checks
        // 44. Missing RBAC in custom hooks
        rbacPatterns.add(Pattern.compile("useCustomHook\\s*\\(.*\\)")); // Custom hook without role checks
        // 45. No role validation in bulk actions
        rbacPatterns.add(Pattern.compile("performBulkAction\\s*\\(.*\\)")); // Bulk actions without checks
        // 46. Hardcoded access tokens
        rbacPatterns.add(Pattern.compile("accessToken\\s*[:=]\\s*['\"].+['\"]")); // Exposed access tokens
        // 47. Missing checks in nested routes
        rbacPatterns.add(Pattern.compile("<NestedRoute\\s*>")); // Nested routes without RBAC
        // 48. No RBAC validation for shared resources
        rbacPatterns.add(Pattern.compile("sharedResource\\s*[:=]\\s*\\w+")); // Shared resources without validation
        // 49. Missing checks for restricted content
        rbacPatterns.add(Pattern.compile("<RestrictedContent\\s*>")); // Restricted content without RBAC
        // 50. Unvalidated role in app initialization
        rbacPatterns.add(Pattern.compile("initializeApp\\s*\\(.*\\)")); // App initialization without role validation

        // Print all patterns for verification
        rbacPatterns.forEach(System.out::println);
    }
}


