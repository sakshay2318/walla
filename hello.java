public static final List<Pattern> strictParameterValidationPatterns = Arrays.asList(

// 1. No validation for numeric parameters in query
Pattern.compile("\\breq\\.query\\.\\w+\\s*(===|==|!=)\\s*.*;?\\b"), // Example: req.query.id == "123"

// 2. Missing validation for request body fields
Pattern.compile("\\breq\\.body\\.\\w+\\s*(===|==|!=|=)\\s*.*;?\\b"), // Example: req.body.username = "admin"

// 3. Input accepted directly without type check
Pattern.compile("\\binput\\s*=\\s*req\\.(query|body|params)\\[\\w+\\];?"), // Example: input = req.body["id"]

// 4. Missing regex checks for email validation
Pattern.compile("\\breq\\.body\\.email\\s*=\\s*.*;?"), // Example: req.body.email = req.query.email

// 5. No length constraint validation for strings
Pattern.compile("\\breq\\.(body|query)\\.\\w+\\.length\\s*\\>\\s*\\d+;?"), // Example: req.body.username.length > 100

// 6. Using parameters directly in database queries
Pattern.compile("\\bdb\\.query\\s*\\(.*\\+\\s*req\\.(body|query|params)\\.\\w+.*\\);?"), // Example: db.query("SELECT * FROM users WHERE id=" + req.query.id)

// 7. Missing checks for allowed characters in strings
Pattern.compile("\\breq\\.(body|query|params)\\.\\w+\\s*=\\s*.*;?"), // Example: req.body.name = req.query.name

// 8. Using unvalidated object properties directly
Pattern.compile("\\bobj\\.\\w+\\s*=\\s*req\\.(body|query|params)\\.\\w+;?"), // Example: obj.id = req.params.id

// 9. Input variables used directly in arithmetic operations
Pattern.compile("\\b\\w+\\s*=\\s*\\w+\\s*\\+\\s*req\\.(body|query|params)\\.\\w+;?"), // Example: total = base + req.query.amount

// 10. Skipped validation for dynamic route parameters
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*\\:(\\w+)\\s*.*\\);?"), // Example: app.get('/user/:id', ...)

// 11. Missing validation for boolean fields
Pattern.compile("\\breq\\.body\\.isEnabled\\s*=\\s*.*;?"), // Example: req.body.isEnabled = req.query.isEnabled

// 12. Missing null/undefined checks for parameters
Pattern.compile("\\bif\\s*\\(\\s*req\\.(body|query|params)\\.\\w+\\s*\\)\\s*\\{?"), // Example: if (req.body.username) { ... }

// 13. Using parameters without range checks
Pattern.compile("\\bif\\s*\\(\\s*req\\.(body|query|params)\\.\\w+\\s*\\>\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.body.age > 18) { ... }

// 14. Directly passing parameters to external APIs
Pattern.compile("\\bapi\\.call\\(.*req\\.(body|query|params)\\.\\w+.*\\);?"), // Example: api.call(req.body.username)

// 15. No check for allowed file extensions in uploads
Pattern.compile("\\bfile\\.name\\s*=\\s*req\\.body\\.file;?"), // Example: file.name = req.body.file

// 16. Missing validation for array inputs
Pattern.compile("\\breq\\.body\\.\\w+\\.forEach\\(.*\\);?"), // Example: req.body.items.forEach(...)

// 17. No sanitization for HTML inputs
Pattern.compile("\\breq\\.body\\.\\w+\\s*=\\s*req\\.query\\.\\w+;?"), // Example: req.body.content = req.query.content

// 18. Dynamic property assignment without checks
Pattern.compile("\\bobj\\[\\w+\\]\\s*=\\s*req\\.(body|query|params)\\.\\w+;?"), // Example: obj[key] = req.body.value

// 19. Missing regex for URL validation
Pattern.compile("\\breq\\.body\\.url\\s*=\\s*.*;?"), // Example: req.body.url = req.query.url

// 20. Missing validation for date fields
Pattern.compile("\\breq\\.body\\.date\\s*=\\s*.*;?"), // Example: req.body.date = req.query.date

// 21. Missing validation for user ID parameters
Pattern.compile("\\bif\\s*\\(\\s*req\\.params\\.id\\s*\\)\\s*\\{?"), // Example: if (req.params.id) { ... }

// 22. No validation for JSON payload structure
Pattern.compile("\\bJSON\\.parse\\(req\\.body\\);?"), // Example: JSON.parse(req.body)

// 23. No validation for token inputs
Pattern.compile("\\breq\\.headers\\.authorization\\s*=\\s*.*;?"), // Example: req.headers.authorization = req.query.token

// 24. Missing checks for enum values
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.type\\s*\\)\\s*\\{?"), // Example: if (req.body.type === "admin") { ... }

// 25. Using inputs directly in system commands
Pattern.compile("\\bexec\\(req\\.(body|query|params)\\.\\w+\\);?"), // Example: exec(req.query.command)

// 26. No length validation for passwords
Pattern.compile("\\breq\\.body\\.password\\.length\\s*\\>\\s*\\d+;?"), // Example: req.body.password.length > 8

// 27. Input used directly in path concatenation
Pattern.compile("\\bfs\\.readFile\\(.*req\\.(body|query|params)\\.\\w+.*\\);?"), // Example: fs.readFile(req.query.filePath)

// 28. No validation for array length
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\.length\\s*\\>\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.body.items.length > 10)

// 29. Missing checks for required fields
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\s*\\)\\s*\\{?"), // Example: if (req.body.email) { ... }

// 30. No validation for nested object properties
Pattern.compile("\\breq\\.body\\.\\w+\\.\\w+\\s*=\\s*.*;?"), // Example: req.body.user.address = req.query.address

// 31. No validation for phone number fields
Pattern.compile("\\breq\\.body\\.phone\\s*=\\s*.*;?"), // Example: req.body.phone = req.query.phone

// 32. Using unvalidated inputs in loops
Pattern.compile("\\bfor\\s*\\(\\s*let\\s+\\w+\\s+of\\s+req\\.body\\.\\w+\\s*\\)\\s*\\{?"), // Example: for (let item of req.body.items)

// 33. Skipped validation for HTTP methods
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*\\);?"), // Example: app.get(...)

// 34. Direct assignment of headers without validation
Pattern.compile("\\breq\\.headers\\.\\w+\\s*=\\s*.*;?"), // Example: req.headers['x-user'] = req.query.user

// 35. No validation for session variables
Pattern.compile("\\bsession\\.\\w+\\s*=\\s*req\\.body\\.\\w+;?"), // Example: session.user = req.body.username

// 36. Skipping validation for route handlers
Pattern.compile("\\brouter\\.(get|post|put|delete)\\(.*\\);?"), // Example: router.get(...)

// 37. No validation for dynamically constructed queries
Pattern.compile("\\bquery\\s*=\\s*req\\.(body|query|params)\\.\\w+;?"), // Example: query = req.query.q

// 38. Missing validation for pagination inputs
Pattern.compile("\\bif\\s*\\(\\s*req\\.query\\.page\\s*\\)\\s*\\{?"), // Example: if (req.query.page) { ... }

// 39. Using inputs directly in URL construction
Pattern.compile("\\burl\\s*=\\s*req\\.(body|query|params)\\.\\w+;?"), // Example: url = req.body.url

// 40. Missing validation for optional fields
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.optionalField\\s*\\)\\s*\\{?"), // Example: if (req.body.optionalField) { ... }

// 41. Directly passing user inputs to third-party services
Pattern.compile("\\bthirdPartyService\\.call\\(req\\.(body|query|params)\\.\\w+\\);?"), // Example: thirdPartyService.call(req.body.username)

// 42. No validation for HTTP status codes in responses
Pattern.compile("\\bres\\.status\\(req\\.body\\.\\w+\\);?"), // Example: res.status(req.body.code)

// 43. Missing type checks for input variables
Pattern.compile("\\bif\\s*\\(\\s*typeof\\s+req\\.body\\.\\w+\\s*!==\\s*['\"]\\w+['\"]\\s*\\)\\s*\\{?"), // Example: if (typeof req.body.age !== "number") { ... }

// 44. No validation for URL parameters
Pattern.compile("\\breq\\.params\\.\\w+\\s*=\\s*.*;?"), // Example: req.params.id = req.query.id

// 45. Skipping validation for file paths
Pattern.compile("\\bfilePath\\s*=\\s*req\\.query\\.\\w+;?"), // Example: filePath = req.query.path

// 46. Missing validation for query strings
Pattern.compile("\\bqueryString\\s*=\\s*req\\.query\\.\\w+;?"), // Example: queryString = req.query.filter

// 47. Using inputs directly in email construction
Pattern.compile("\\bemail\\s*=\\s*req\\.body\\.\\w+;?"), // Example: email = req.body.email

// 48. No validation for date ranges
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.date\\s*\\>\\s*.*\\)\\s*\\{?"), // Example: if (req.body.date > new Date()) { ... }

// 49. Skipped validation for configuration inputs
Pattern.compile("\\bconfig\\s*=\\s*req\\.body\\.\\w+;?"), // Example: config = req.body.settings

// 50. No validation for nested array properties
Pattern.compile("\\breq\\.body\\.\\w+\\.\\w+\\.\\w+\\s*=\\s*.*;?") // Example: req.body.user.address.city = req.query.city

);
public static final List<Pattern> strictParameterValidationPatterns = Arrays.asList(

// 51. Missing validation for optional query parameters
Pattern.compile("\\breq\\.query\\.\\w+\\s*=\\s*.*;?"), // Example: req.query.filter = "value"

// 52. No range validation for numeric inputs
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\s*(>|<|>=|<=)\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.body.age > 60) { ... }

// 53. Directly concatenating user input in strings
Pattern.compile("\\bmessage\\s*=\\s*`.*\\$\\{req\\.\\w+\\.\\w+\\}.*`;?"), // Example: `Welcome ${req.body.name}`

// 54. Missing validation for boolean query parameters
Pattern.compile("\\breq\\.query\\.\\w+\\s*=\\s*.*(true|false).*;?"), // Example: req.query.isActive = true

// 55. Skipping checks for input array elements
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\[\\d+\\]\\s*\\)\\s*\\{?"), // Example: if (req.body.items[0]) { ... }

// 56. Input used directly in string comparison
Pattern.compile("\\bif\\s*\\(\\s*req\\.(body|query|params)\\.\\w+\\s*(===|!==)\\s*['\"].*['\"]\\s*\\)\\s*\\{?"), // Example: if (req.query.role === "admin") { ... }

// 57. Missing validation for date-time inputs
Pattern.compile("\\bnew\\s+Date\\(req\\.(body|query|params)\\.\\w+\\);?"), // Example: new Date(req.body.date)

// 58. Using input without sanitizing special characters
Pattern.compile("\\binput\\s*=\\s*req\\.\\w+\\.\\w+;?"), // Example: input = req.body.username

// 59. No whitelist enforcement for accepted parameters
Pattern.compile("\\bif\\s*\\(\\s*!\\[(.*)\\]\\.includes\\(req\\.\\w+\\.\\w+\\)\\s*\\)\\s*\\{?"), // Example: if (!["admin", "user"].includes(req.body.role)) { ... }

// 60. Missing validation for nested arrays
Pattern.compile("\\breq\\.body\\.\\w+\\[\\d+\\]\\.\\w+\\s*=\\s*.*;?"), // Example: req.body.items[0].name = "item"

// 61. Skipped validation for wildcard route parameters
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*\\:\\w+.*\\);?"), // Example: app.get('/user/:id', ...)

// 62. Direct use of parameters in regular expressions
Pattern.compile("\\bRegExp\\(req\\.\\w+\\.\\w+\\);?"), // Example: new RegExp(req.query.regex)

// 63. No validation for deeply nested object fields
Pattern.compile("\\breq\\.body\\.\\w+\\.\\w+\\.\\w+\\s*=\\s*.*;?"), // Example: req.body.user.address.city = req.query.city

// 64. Missing type checks for query parameters
Pattern.compile("\\bif\\s*\\(\\s*typeof\\s+req\\.query\\.\\w+\\s*!==\\s*['\"]\\w+['\"]\\s*\\)\\s*\\{?"), // Example: if (typeof req.query.page !== "number") { ... }

// 65. Using input directly in JSON object keys
Pattern.compile("\\bconst\\s+\\w+\\s*=\\s*{\\s*\\[req\\.\\w+\\.\\w+\\]:.*\\s*};?"), // Example: { [req.query.key]: value }

// 66. No validation for dynamically assigned object keys
Pattern.compile("\\bobj\\[req\\.\\w+\\.\\w+\\]\\s*=\\s*.*;?"), // Example: obj[req.body.key] = "value"

// 67. No character limit enforced for text fields
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\.length\\s*>\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.body.comment.length > 500) { ... }

// 68. Direct usage of query parameters in object instantiation
Pattern.compile("\\bnew\\s+\\w+\\(.*req\\.query\\.\\w+.*\\);?"), // Example: new User(req.query.username)

// 69. Skipped checks for undefined inputs
Pattern.compile("\\bif\\s*\\(req\\.\\w+\\.\\w+\\s*==\\s*undefined\\)\\s*\\{?"), // Example: if (req.body.name == undefined) { ... }

// 70. Missing validation for input used in mathematical operations
Pattern.compile("\\bresult\\s*=\\s*req\\.\\w+\\.\\w+\\s*[+-/*%]\\s*\\d+;?"), // Example: result = req.body.value + 10

// 71. No check for null input in nested properties
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.\\w+\\s*==\\s*null\\)\\s*\\{?"), // Example: if (req.body.user.address == null) { ... }

// 72. Using inputs directly in string concatenation
Pattern.compile("\\bmessage\\s*=\\s*req\\.body\\.\\w+\\s*\\+\\s*['\"].*['\"];?"), // Example: message = req.body.name + " logged in"

// 73. No validation for query parameter lengths
Pattern.compile("\\bif\\s*\\(\\s*req\\.query\\.\\w+\\.length\\s*>\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.query.search.length > 100) { ... }

// 74. Skipping regex validation for required fields
Pattern.compile("\\bif\\s*\\(\\s*!/.*\\/.test\\(req\\.body\\.\\w+\\)\\s*\\)\\s*\\{?"), // Example: if (!/^[a-z0-9]+$/.test(req.body.username)) { ... }

// 75. No validation for HTTP request methods
Pattern.compile("\\bapp\\.(get|post|put|delete)\\s*\\(.*\\);?"), // Example: app.get(...)

// 76. Using inputs directly in array initialization
Pattern.compile("\\bconst\\s+\\w+\\s*=\\s*\\[req\\.\\w+\\.\\w+\\];?"), // Example: const items = [req.body.value]

// 77. No checks for max length of URL inputs
Pattern.compile("\\bif\\s*\\(req\\.body\\.url\\.length\\s*>\\s*\\d+\\)\\s*\\{?"), // Example: if (req.body.url.length > 2048) { ... }

// 78. No validation for input before JSON.stringify
Pattern.compile("\\bJSON\\.stringify\\(req\\.body\\.\\w+\\);?"), // Example: JSON.stringify(req.body.user)

// 79. Skipped checks for negative numbers in numeric inputs
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*<\\s*0\\)\\s*\\{?"), // Example: if (req.body.amount < 0) { ... }

// 80. Missing validation for string to number conversion
Pattern.compile("\\bNumber\\(req\\.query\\.\\w+\\);?"), // Example: Number(req.query.page)

// 81. Using inputs directly in file paths
Pattern.compile("\\bfs\\.readFileSync\\(req\\.query\\.\\w+\\);?"), // Example: fs.readFileSync(req.query.path)

// 82. No validation for base64-encoded inputs
Pattern.compile("\\bBuffer\\.from\\(req\\.body\\.\\w+\\);?"), // Example: Buffer.from(req.body.image)

// 83. Skipped checks for required query parameters
Pattern.compile("\\bif\\s*\\(\\s*req\\.query\\.\\w+\\)\\s*\\{?"), // Example: if (req.query.filter) { ... }

// 84. Missing validation for non-empty string inputs
Pattern.compile("\\bif\\s*\\(\\s*req\\.body\\.\\w+\\.trim\\(\\)\\.length\\s*>\\s*0\\s*\\)\\s*\\{?"), // Example: if (req.body.name.trim().length > 0) { ... }

// 85. No regex validation for password strength
Pattern.compile("\\bif\\s*\\(\\s*!/.*\\/.test\\(req\\.body\\.password\\)\\s*\\)\\s*\\{?"), // Example: if (!/^(?=.*[A-Za-z])(?=.*\\d).{8,}$/.test(req.body.password)) { ... }

// 86. Using inputs directly in object destructuring
Pattern.compile("\\bconst\\s+\\{\\s*\\w+\\s*}\\s*=\\s*req\\.\\w+;?"), // Example: const { username } = req.body

// 87. Missing validation for integer-only parameters
Pattern.compile("\\bparseInt\\(req\\.query\\.\\w+\\);?"), // Example: parseInt(req.query.page)

// 88. Skipped validation for optional nested fields
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\?.\\w+\\s*\\)\\s*\\{?"), // Example: if (req.body.user?.address) { ... }

// 89. Using inputs directly in encryption keys
Pattern.compile("\\bcrypt\\.hashSync\\(req\\.body\\.\\w+,.*\\);?"), // Example: bcrypt.hashSync(req.body.password, salt)

// 90. No validation for special characters in usernames
Pattern.compile("\\bif\\s*\\(\\s*!/^[a-zA-Z0-9_]+$/.test\\(req\\.body\\.username\\)\\s*\\)\\s*\\{?"), // Example: if (!/^[a-zA-Z0-9_]+$/.test(req.body.username)) { ... }

// 91. Missing validation for deeply nested lists
Pattern.compile("\\breq\\.body\\.\\w+\\[\\d+\\]\\.\\w+\\.\\w+\\s*=\\s*.*;?"), // Example: req.body.items[0].metadata.value = "value"

// 92. No validation for dynamic imports
Pattern.compile("\\bimport\\(req\\.query\\.\\w+\\);?"), // Example: import(req.query.module)

// 93. Missing validation for multipart form data
Pattern.compile("\\breq\\.files\\.\\w+\\s*=\\s*.*;?"), // Example: req.files.image = "file.jpg"

// 94. Using inputs directly in HTTP headers
Pattern.compile("\\bres\\.set\\(req\\.query\\.\\w+,.*\\);?"), // Example: res.set(req.query.header, "value")

// 95. Skipping regex validation for phone numbers
Pattern.compile("\\bif\\s*\\(\\s*!/^[0-9]{10}$/.test\\(req\\.body\\.phone\\)\\s*\\)\\s*\\{?"), // Example: if (!/^[0-9]{10}$/.test(req.body.phone)) { ... }

// 96. Missing validation for undefined route variables
Pattern.compile("\\breq\\.params\\.\\w+\\s*=\\s*.*;?"), // Example: req.params.id = "user1"

// 97. Using inputs directly in cache keys
Pattern.compile("\\bcache\\.set\\(req\\.query\\.\\w+,.*\\);?"), // Example: cache.set(req.query.key, value)

// 98. Skipped validation for integer ranges
Pattern.compile("\\bif\\s*\\(\\s*req\\.query\\.\\w+\\s*>=\\s*\\d+\\s*\\)\\s*\\{?"), // Example: if (req.query.page >= 1) { ... }

// 99. No validation for user-provided sort order
Pattern.compile("\\bsort\\(\\s*req\\.query\\.\\w+\\s*\\);?"), // Example: sort(req.query.order)

// 100. Missing validation for environment variable overrides
Pattern.compile("\\bprocess\\.env\\.\\w+\\s*=\\s*req\\.query\\.\\w+;?") // Example: process.env.API_KEY = req.query.key

);
