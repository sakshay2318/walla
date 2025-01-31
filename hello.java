public static final List<Pattern> whitelistValidationPatterns = Arrays.asList(

// 1. Direct usage of input IDs without validation
Pattern.compile("\\breq\\.(body|query|params)\\.\\w+\\s*=\\s*.*;?"), // Example: req.params.userId = "inputValue"

// 2. Skipped whitelist validation for database IDs
Pattern.compile("\\bUser\\.findById\\(req\\.params\\.\\w+\\);?"), // Example: User.findById(req.params.id)

// 3. No check for ID existence in database query
Pattern.compile("\\bdb\\.collection\\(.*\\)\\.findOne\\({\\s*id:\\s*req\\.params\\.\\w+\\s*}\\);?"), // Example: db.collection('users').findOne({ id: req.params.id })

// 4. Missing ID verification before accessing data
Pattern.compile("\\bgetUserData\\(req\\.params\\.\\w+\\);?"), // Example: getUserData(req.params.id)

// 5. Direct comparison of IDs without validation
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*===\\s*['\"].*['\"]\\)\\s*\\{?"), // Example: if (req.params.id === "admin") { ... }

// 6. Skipped validation for optional object references
Pattern.compile("\\bobj\\.\\w+\\s*=\\s*req\\.\\w+\\.\\w+;?"), // Example: obj.userId = req.body.userId

// 7. No query to validate ID before use
Pattern.compile("\\bModel\\.find\\({\\s*\\w+:\\s*req\\.params\\.\\w+\\s*}\\);?"), // Example: User.find({ id: req.params.id })

// 8. Using IDs directly in sensitive actions
Pattern.compile("\\bdeleteUser\\(req\\.params\\.\\w+\\);?"), // Example: deleteUser(req.params.id)

// 9. Missing check for valid foreign keys
Pattern.compile("\\baddForeignKey\\(req\\.body\\.\\w+\\);?"), // Example: addForeignKey(req.body.userId)

// 10. Skipped ID validation for RESTful actions
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*\\:\\w+.*\\);?"), // Example: app.get('/user/:id', ...)

// 11. Using user-provided IDs in join queries
Pattern.compile("\\bdb\\.query\\(.*JOIN.*ON.*req\\.\\w+\\.\\w+.*\\);?"), // Example: SELECT * FROM orders JOIN users ON users.id = req.params.id

// 12. Skipping validation for input arrays containing IDs
Pattern.compile("\\bids\\s*=\\s*req\\.body\\.\\w+;?"), // Example: ids = req.body.userIds

// 13. No existence check for referenced IDs in multiple records
Pattern.compile("\\bModel\\.find\\({\\s*\\w+:\\s*\\{\\s*\\$in:\\s*req\\.body\\.\\w+\\s*}\\s*}\\);?"), // Example: User.find({ id: { $in: req.body.ids } })

// 14. Skipped check for undefined IDs
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*==\\s*undefined\\)\\s*\\{?"), // Example: if (req.params.id == undefined) { ... }

// 15. Using IDs directly in file operations
Pattern.compile("\\bfs\\.readFileSync\\(req\\.params\\.\\w+\\);?"), // Example: fs.readFileSync(req.params.path)

// 16. No check for valid IDs in URL params
Pattern.compile("\\bconst\\s+id\\s*=\\s*req\\.params\\.\\w+;?"), // Example: const id = req.params.userId

// 17. Using input IDs directly in filters
Pattern.compile("\\bfilter\\s*=\\s*req\\.body\\.\\w+;?"), // Example: filter = req.body.filterId

// 18. Skipping range checks for numeric IDs
Pattern.compile("\\bif\\s*\\(req\\.query\\.\\w+\\s*<\\s*\\d+\\)\\s*\\{?"), // Example: if (req.query.id < 100) { ... }

// 19. Missing ID verification in complex queries
Pattern.compile("\\bModel\\.findOne\\(.*req\\.\\w+\\.\\w+.*\\);?"), // Example: Model.findOne({ id: req.params.id })

// 20. Skipped regex validation for UUID format
Pattern.compile("\\bif\\s*\\(\\s*!/^[a-f0-9-]{36}$/.test\\(req\\.\\w+\\.\\w+\\)\\s*\\)\\s*\\{?"), // Example: if (!/^[a-f0-9-]{36}$/.test(req.params.id)) { ... }

// 21. No validation for dynamically assigned object keys
Pattern.compile("\\bobj\\[req\\.\\w+\\.\\w+\\]\\s*=\\s*.*;?"), // Example: obj[req.params.key] = value

// 22. Using input IDs directly in URL generation
Pattern.compile("\\bconst\\s+url\\s*=\\s*`.*\\$\\{req\\.\\w+\\.\\w+\\}.*`;?"), // Example: const url = `/user/${req.params.id}`

// 23. No validation for foreign keys in relationships
Pattern.compile("\\bModel\\.findByIdAndUpdate\\(req\\.body\\.\\w+,\\s*.*\\);?"), // Example: Model.findByIdAndUpdate(req.body.userId, ...)

// 24. Skipping validation for required nested IDs
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.\\w+\\s*\\)\\s*\\{?"), // Example: if (req.body.user.id) { ... }

// 25. No existence check for query parameters referencing IDs
Pattern.compile("\\bdb\\.query\\(.*WHERE.*req\\.query\\.\\w+.*\\);?"), // Example: SELECT * FROM users WHERE id = req.query.userId

// 26. Missing validation for input objects containing IDs
Pattern.compile("\\bconst\\s+input\\s*=\\s*req\\.body;?"), // Example: const input = req.body

// 27. Using user-provided IDs in encryption keys
Pattern.compile("\\bcrypt\\.hashSync\\(req\\.body\\.\\w+,.*\\);?"), // Example: bcrypt.hashSync(req.body.id, salt)

// 28. Skipped validation for pagination IDs
Pattern.compile("\\bif\\s*\\(req\\.query\\.\\w+\\s*>\\s*\\d+\\)\\s*\\{?"), // Example: if (req.query.page > 10) { ... }

// 29. Missing checks for ID lengths
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.length\\s*>\\s*\\d+\\)\\s*\\{?"), // Example: if (req.body.userId.length > 36) { ... }

// 30. Using IDs directly in array manipulations
Pattern.compile("\\bconst\\s+ids\\s*=\\s*\\[req\\.body\\.\\w+\\];?"), // Example: const ids = [req.body.id]

// 31. No existence check for deeply nested IDs
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.\\w+\\.\\w+\\s*\\)\\s*\\{?"), // Example: if (req.body.user.address.id) { ... }

// 32. Skipping ID validation in aggregation pipelines
Pattern.compile("\\bModel\\.aggregate\\(.*req\\.body\\.\\w+.*\\);?"), // Example: Model.aggregate([{ $match: { userId: req.body.id } }])

// 33. Missing validation for dynamic filters
Pattern.compile("\\bconst\\s+filter\\s*=\\s*req\\.body\\.\\w+;?"), // Example: const filter = req.body.filter

// 34. No whitelist enforcement for valid IDs
Pattern.compile("\\bif\\s*\\(\\s*!\\[(.*)\\]\\.includes\\(req\\.\\w+\\.\\w+\\)\\s*\\)\\s*\\{?"), // Example: if (!["admin", "user"].includes(req.params.role)) { ... }

// 35. Skipped checks for invalid characters in IDs
Pattern.compile("\\bif\\s*\\(\\s*!/^[a-zA-Z0-9_-]+$/.test\\(req\\.params\\.\\w+\\)\\s*\\)\\s*\\{?"), // Example: if (!/^[a-zA-Z0-9_-]+$/.test(req.params.id)) { ... }

// 36. Using IDs directly in sensitive updates
Pattern.compile("\\bModel\\.update\\({\\s*id:\\s*req\\.params\\.\\w+\\s*},.*\\);?"), // Example: Model.update({ id: req.params.id }, ...)

// 37. Skipping validation for numeric-only IDs
Pattern.compile("\\bNumber\\(req\\.params\\.\\w+\\);?"), // Example: Number(req.params.id)

// 38. No validation for undefined foreign keys
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*==\\s*null\\)\\s*\\{?"), // Example: if (req.body.foreignKey == null) { ... }

// 39. Using inputs directly in filter conditions
Pattern.compile("\\bconst\\s+query\\s*=\\s*{\\s*\\w+:\\s*req\\.body\\.\\w+\\s*};?"), // Example: const query = { userId: req.body.userId }

// 40. Skipped check for ID constraints
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*>\\s*1000\\)\\s*\\{?"), // Example: if (req.params.id > 1000) { ... }

// 41. No validation for multi-object references
Pattern.compile("\\bconst\\s+ids\\s*=\\s*req\\.body\\.\\w+;?"), // Example: const ids = req.body.objectIds

// 42. Using IDs directly in caching mechanisms
Pattern.compile("\\bcache\\.set\\(req\\.params\\.\\w+,.*\\);?"), // Example: cache.set(req.params.id, value)

// 43. Missing validation for dynamic sort fields
Pattern.compile("\\bsort\\(\\s*req\\.query\\.\\w+\\);?"), // Example: sort(req.query.field)

// 44. Skipped validation for undefined pagination IDs
Pattern.compile("\\bif\\s*\\(req\\.query\\.\\w+\\s*==\\s*undefined\\)\\s*\\{?"), // Example: if (req.query.page == undefined) { ... }

// 45. No existence check for sensitive ID fields
Pattern.compile("\\bconst\\s+user\\s*=\\s*req\\.body\\.\\w+;?"), // Example: const user = req.body.userId

// 46. Using IDs directly in dynamic keys
Pattern.compile("\\bconst\\s+key\\s*=\\s*req\\.params\\.\\w+;?"), // Example: const key = req.params.id

// 47. Missing ID validation in dynamic conditions
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*!=\\s*req\\.query\\.\\w+\\)\\s*\\{?"), // Example: if (req.params.id != req.query.id) { ... }

// 48. No validation for user-generated dynamic properties
Pattern.compile("\\bobj\\[req\\.body\\.\\w+\\]\\s*=\\s*.*;?"), // Example: obj[req.body.key] = value

// 49. Skipped validation for JSON-passed IDs
Pattern.compile("\\bJSON\\.parse\\(req\\.body\\.\\w+\\);?"), // Example: JSON.parse(req.body.data)

// 50. Using unverified IDs in external API calls
Pattern.compile("\\baxios\\.get\\(`.*\\$\\{req\\.params\\.\\w+\\}.*`\\);?") // Example: axios.get(`/api/users/${req.params.id}`)

);
public static final List<Pattern> whitelistValidationPatterns = Arrays.asList(

// 51. Missing validation for directly assigned IDs in HTTP requests
Pattern.compile("\\baxios\\.(get|post|put|delete)\\(.*req\\.params\\.\\w+.*\\);?"), // Example: axios.get(`/api/users/${req.params.id}`)

// 52. Skipping validation for object keys passed from inputs
Pattern.compile("\\bobj\\[req\\.params\\.\\w+\\]\\s*=\\s*.*;?"), // Example: obj[req.params.key] = value

// 53. No check for valid ID format in filter conditions
Pattern.compile("\\bconst\\s+filter\\s*=\\s*{\\s*id:\\s*req\\.body\\.\\w+\\s*};?"), // Example: const filter = { id: req.body.id }

// 54. Using IDs directly in transaction handlers
Pattern.compile("\\bdb\\.transaction\\(.*req\\.params\\.\\w+.*\\);?"), // Example: db.transaction({ id: req.params.id })

// 55. Missing validation for array inputs with IDs
Pattern.compile("\\bconst\\s+ids\\s*=\\s*req\\.body\\.\\w+;?"), // Example: const ids = req.body.ids

// 56. Direct assignment of unverified IDs to variables
Pattern.compile("\\bconst\\s+id\\s*=\\s*req\\.query\\.\\w+;?"), // Example: const id = req.query.userId

// 57. No validation for deeply nested object properties containing IDs
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.\\w+\\.\\w+\\)\\s*\\{?"), // Example: if (req.body.user.address.id) { ... }

// 58. Using IDs directly in dynamic field updates
Pattern.compile("\\bdb\\.update\\(\\{\\s*id:\\s*req\\.params\\.\\w+\\s*},.*\\);?"), // Example: db.update({ id: req.params.id }, ...)

// 59. Skipping validation for dynamic array filters
Pattern.compile("\\bModel\\.find\\(\\{\\s*\\w+:\\s*\\{\\s*\\$in:\\s*req\\.body\\.\\w+\\s*}\\}\\);?"), // Example: User.find({ id: { $in: req.body.ids } })

// 60. Missing checks for undefined IDs in nested objects
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\.\\w+\\s*==\\s*undefined\\)\\s*\\{?"), // Example: if (req.body.user.id == undefined) { ... }

// 61. Using IDs directly in database migrations
Pattern.compile("\\bdb\\.migrate\\(.*req\\.params\\.\\w+.*\\);?"), // Example: db.migrate({ userId: req.params.id })

// 62. No validation for string-to-ID conversions
Pattern.compile("\\bparseInt\\(req\\.params\\.\\w+\\);?"), // Example: parseInt(req.params.id)

// 63. Skipping validation for query parameters containing IDs
Pattern.compile("\\bif\\s*\\(req\\.query\\.\\w+\\s*!=\\s*null\\)\\s*\\{?"), // Example: if (req.query.userId != null) { ... }

// 64. Missing whitelist for allowed status updates
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*==\\s*['\"].*['\"]\\)\\s*\\{?"), // Example: if (req.body.status == "approved") { ... }

// 65. Direct assignment of inputs to primary key fields
Pattern.compile("\\bobj\\.id\\s*=\\s*req\\.params\\.\\w+;?"), // Example: obj.id = req.params.userId

// 66. Using unverified IDs in custom hooks
Pattern.compile("\\buseEffect\\(\\(.*\\)=>\\{.*req\\.params\\.\\w+.*\\}\\);?"), // Example: useEffect(() => { fetch(`/user/${req.params.id}`) })

// 67. Missing validation for numeric range of IDs
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*<\\s*0\\)\\s*\\{?"), // Example: if (req.params.id < 0) { ... }

// 68. Using input IDs in API gateway routing without checks
Pattern.compile("\\bapiGateway\\.route\\(.*req\\.params\\.\\w+.*\\);?"), // Example: apiGateway.route({ path: `/user/${req.params.id}` })

// 69. Skipped validation for user-provided keys in maps
Pattern.compile("\\bmap\\[req\\.body\\.\\w+\\]\\s*=\\s*.*;?"), // Example: map[req.body.key] = value

// 70. No verification for array indexes passed as IDs
Pattern.compile("\\barray\\[req\\.query\\.\\w+\\]\\s*=\\s*.*;?"), // Example: array[req.query.index] = value

// 71. Using IDs directly in string formatting without checks
Pattern.compile("\\bconsole\\.log\\(.*req\\.params\\.\\w+.*\\);?"), // Example: console.log(`User ID: ${req.params.id}`)

// 72. Skipped validation for dynamic joins in queries
Pattern.compile("\\bdb\\.query\\(.*JOIN.*req\\.params\\.\\w+.*\\);?"), // Example: SELECT * FROM users JOIN orders ON orders.userId = req.params.id

// 73. Missing check for undefined keys in nested arrays
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\[\\d+\\]\\s*==\\s*undefined\\)\\s*\\{?"), // Example: if (req.body.users[0] == undefined) { ... }

// 74. Directly passing IDs to third-party APIs without validation
Pattern.compile("\\bfetch\\(`.*\\$\\{req\\.query\\.\\w+\\}.*`\\);?"), // Example: fetch(`/api/${req.query.userId}`)

// 75. Missing validation for filter objects in aggregation pipelines
Pattern.compile("\\baggregate\\(.*\\$match.*req\\.body\\.\\w+.*\\);?"), // Example: aggregate([{ $match: { userId: req.body.id } }])

// 76. Skipping validation for JSON field updates
Pattern.compile("\\bjsonObj\\.\\w+\\s*=\\s*req\\.body\\.\\w+;?"), // Example: jsonObj.id = req.body.userId

// 77. Using input IDs directly in indexing operations
Pattern.compile("\\bindex\\s*=\\s*req\\.query\\.\\w+;?"), // Example: index = req.query.index

// 78. Missing checks for allowed operations based on IDs
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*===\\s*['\"].*['\"]\\)\\s*\\{?"), // Example: if (req.body.action === "delete") { ... }

// 79. No validation for dynamic fields in updates
Pattern.compile("\\bupdate\\s*=\\s*req\\.body\\.\\w+;?"), // Example: update = req.body.field

// 80. Skipping validation for user-provided URL parameters
Pattern.compile("\\burl\\s*=\\s*`.*\\$\\{req\\.params\\.\\w+\\}.*`;?"), // Example: url = `/user/${req.params.id}`

// 81. Direct assignment of unverified IDs in middleware
Pattern.compile("\\bnext\\(req\\.body\\.\\w+\\);?"), // Example: next(req.body.userId)

// 82. Missing check for invalid characters in ID inputs
Pattern.compile("\\bif\\s*\\(\\s*!/^[a-zA-Z0-9]+$/.test\\(req\\.query\\.\\w+\\)\\)\\s*\\{?"), // Example: if (!/^[a-zA-Z0-9]+$/.test(req.query.id)) { ... }

// 83. Using IDs directly in cache keys
Pattern.compile("\\bcache\\.set\\(req\\.params\\.\\w+,.*\\);?"), // Example: cache.set(req.params.id, value)

// 84. Skipping validation for custom object updates
Pattern.compile("\\bobj\\[req\\.body\\.\\w+\\]\\s*=\\s*.*;?"), // Example: obj[req.body.key] = value

// 85. No checks for undefined input properties
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*==\\s*null\\)\\s*\\{?"), // Example: if (req.body.userId == null) { ... }

// 86. Directly using IDs in error handling conditions
Pattern.compile("\\bif\\s*\\(req\\.params\\.\\w+\\s*!=\\s*null\\)\\s*\\{?"), // Example: if (req.params.id != null) { ... }

// 87. Missing ID validation for sensitive configuration updates
Pattern.compile("\\bconfig\\.update\\(\\{\\s*\\w+:\\s*req\\.body\\.\\w+\\}\\);?"), // Example: config.update({ userId: req.body.id })

// 88. Using IDs in dynamic array indexing without validation
Pattern.compile("\\bdata\\[req\\.body\\.\\w+\\]\\s*=\\s*.*;?"), // Example: data[req.body.index] = value

// 89. No validation for user-defined operations
Pattern.compile("\\boperation\\s*=\\s*req\\.query\\.\\w+;?"), // Example: operation = req.query.action

// 90. Skipped checks for invalid numeric values in IDs
Pattern.compile("\\bif\\s*\\(req\\.query\\.\\w+\\s*<\\s*0\\)\\s*\\{?"), // Example: if (req.query.userId < 0) { ... }

// 91. Using unverified IDs in multiple request handlers
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*req\\.params\\.\\w+.*\\);?"), // Example: app.get(`/user/${req.params.id}`, ...)

// 92. No validation for range-based ID filters
Pattern.compile("\\bconst\\s+range\\s*=\\s*{\\s*start:\\s*req\\.query\\.\\w+,\\s*end:\\s*req\\.query\\.\\w+\\s*};?"), // Example: const range = { start: req.query.startId, end: req.query.endId }

// 93. Skipping validation for regex-based ID patterns
Pattern.compile("\\bif\\s*\\(!/regex/.test\\(req\\.query\\.\\w+\\)\\)\\s*\\{?"), // Example: if (!/regex/.test(req.query.id)) { ... }

// 94. Directly assigning IDs to loop indices
Pattern.compile("\\bfor\\s*\\(let\\s+i\\s*=\\s*req\\.query\\.\\w+;\\s*i\\s*<\\s*.*;\\s*i\\+\\+\\)"), // Example: for (let i = req.query.startId; i < 100; i++)

// 95. No validation for sort keys in dynamic lists
Pattern.compile("\\blist\\.sort\\(req\\.query\\.\\w+\\);?"), // Example: list.sort(req.query.sortKey)

// 96. Missing ID validation in module imports
Pattern.compile("\\bimport\\s+.*\\s+from\\s+`.*\\$\\{req\\.params\\.\\w+\\}.*`;?"), // Example: import module from `/path/${req.params.id}`

// 97. Skipped validation for batch updates with IDs
Pattern.compile("\\bupdateBatch\\(\\{\\s*\\w+:\\s*req\\.body\\.\\w+\\}\\);?"), // Example: updateBatch({ userId: req.body.id })

// 98. Directly concatenating IDs in strings
Pattern.compile("\\bconst\\s+message\\s*=\\s*`.*\\$\\{req\\.params\\.\\w+\\}.*`;?"), // Example: const message = `User ID: ${req.params.id}`

// 99. Missing checks for numeric constraints in body parameters
Pattern.compile("\\bif\\s*\\(req\\.body\\.\\w+\\s*\\<\\s*0\\)\\s*\\{?"), // Example: if (req.body.userId < 0) { ... }

// 100. Using IDs directly in sensitive logging operations
Pattern.compile("\\blogger\\.info\\(.*req\\.params\\.\\w+.*\\);?") // Example: logger.info(`User ID: ${req.params.id}`)
);
