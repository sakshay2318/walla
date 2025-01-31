public static final List<Pattern> idorPatterns = Arrays.asList(
// 1. ID in URL paths
Pattern.compile("\\/\\w+\\/\\d+"), // Example: /user/123

// 2. Nested paths with IDs
Pattern.compile("\\/\\w+\\/\\w+\\/\\d+"), // Example: /user/profile/123

// 3. Query parameter IDs
Pattern.compile("id=\\d+"), // Example: ?id=123

// 4. User ID in objects
Pattern.compile("userId\\s*:\\s*\\d+"), // Example: userId: 123

// 5. Request parameters
Pattern.compile("\\.params\\.(id|userId|orderId)"), // Example: req.params.id

// 6. Request query parameters
Pattern.compile("\\.query\\.(id|userId|orderId)"), // Example: req.query.id

// 7. Request body fields
Pattern.compile("\\.body\\.(id|userId|orderId)"), // Example: req.body.id

// 8. Header authorization tokens
Pattern.compile("\\.headers\\.(Authorization|authToken)"), // Example: req.headers.Authorization

// 9. API calls with interpolated IDs
Pattern.compile("(?:fetch|axios)\\((['\"`]).*(\\{id\\}|\\{userId\\})\\1"), // Example: fetch(`/api/user/${id}`)

// 10. Path assignments
Pattern.compile("path=.*\\/\\d+"), // Example: path=/user/123

// 11. Account ID in queries
Pattern.compile("accountId=\\d+"), // Example: ?accountId=456

// 12. Header fields with user or account IDs
Pattern.compile("\\.headers\\.(x-user-id|x-account-id)"), // Example: req.headers['x-user-id']

// 13. Accounts with IDs
Pattern.compile("accounts\\/\\d+"), // Example: /accounts/789

// 14. Customer ID in objects
Pattern.compile("customerId\\s*:\\s*\\d+"), // Example: customerId: 987

// 15. Employee ID in objects
Pattern.compile("employeeId\\s*:\\s*\\d+"), // Example: employeeId: 654

// 16. User parameter in URLs
Pattern.compile("user=(\\d+)"), // Example: user=321

// 17. Dynamic URL paths
Pattern.compile("\\/api\\/\\w+\\/\\{\\w+}\\/\\d+"), // Example: /api/order/{orderId}/123

// 18. Hardcoded IDs in code
Pattern.compile("([\"'`])id\\1:\\s*\\d+"), // Example: 'id': 123

// 19. Nested ID query parameters
Pattern.compile("nested.id=\\d+"), // Example: ?nested.id=456

// 20. Multi-level ID fields
Pattern.compile("details\\.id\\s*:\\s*\\d+"), // Example: details.id: 789

// 21. Key-value pairs with IDs
Pattern.compile("\\['id']\\s*:\\s*\\d+"), // Example: ['id']: 123

// 22. Tokenized IDs
Pattern.compile("\\bid_token=\\w+"), // Example: ?id_token=abc123

// 23. Form data containing IDs
Pattern.compile("formData\\.append\\(['\"`]id['\"`],\\s*\\d+"), // Example: formData.append('id', 123)

// 24. Object destructuring for IDs
Pattern.compile("\\{\\s*id:\\s*\\d+"), // Example: { id: 123 }

// 25. Encoded IDs in paths
Pattern.compile("encodeURI\\(.+\\/\\d+\\)"), // Example: encodeURI('/user/123')

// 26. Unvalidated resource paths
Pattern.compile("resourcePath=\\w+\\/\\d+"), // Example: ?resourcePath=user/123

// 27. Profile-specific IDs
Pattern.compile("\\/profile\\/\\d+"), // Example: /profile/456

// 28. User ID in serialized objects
Pattern.compile("\"userId\":\\s*\\d+"), // Example: "userId": 123

// 29. Embedded resource paths
Pattern.compile("\\/embedded\\/resource\\/\\d+"), // Example: /embedded/resource/789

// 30. Inline ID parameters
Pattern.compile("inline_id=\\d+"), // Example: ?inline_id=123

// 31. API paths with user/account identifiers
Pattern.compile("\\/api\\/user\\/\\d+"), // Example: /api/user/321

// 32. RESTful API patterns
Pattern.compile("\\/api\\/\\w+\\/\\d+$"), // Example: /api/data/123

// 33. Angular-style route parameters
Pattern.compile("\\:\\w+\\/\\d+"), // Example: :id/123

// 34. Backbone.js route definitions
Pattern.compile("routes\\s*:\\s*\\{\\s*\\'\\w+\\/\\:id\\'"), // Example: routes: {'user/:id'}

// 35. Dynamically loaded user data
Pattern.compile("\\{userId:\\s*\\d+"), // Example: {userId: 123}

// 36. Tokenized resources
Pattern.compile("resource_token=\\w+"), // Example: ?resource_token=abc123

// 37. Chained parameters with IDs
Pattern.compile("\\/\\w+\\/(\\d+)\\/\\w+"), // Example: /user/123/orders

// 38. Sensitive file IDs
Pattern.compile("file_id=\\d+"), // Example: ?file_id=456

// 39. Direct user reference
Pattern.compile("directUser=(\\d+)"), // Example: directUser=789

// 40. References in header fields
Pattern.compile("\\.headers\\['X-ID'\\]"), // Example: req.headers['X-ID']

// 41. Inline account details
Pattern.compile("accountDetails\\.id\\s*:\\s*\\d+"), // Example: accountDetails.id: 123

// 42. Embedded object IDs
Pattern.compile("embedded\\.object\\.id=\\d+"), // Example: embedded.object.id=456

// 43. Custom user tokens
Pattern.compile("user_token=\\w+"), // Example: ?user_token=abc123

// 44. Direct resource access
Pattern.compile("\\/resource\\/access\\/\\d+"), // Example: /resource/access/789

// 45. UUID usage (IDOR still possible if misused)
Pattern.compile("uuid\\s*:\\s*\\'\\w+-\\w+-\\w+-\\w+-\\w+'"), // Example: uuid: '123e4567-e89b-12d3-a456-426614174000'

// 46. Access-controlled files
Pattern.compile("\\/files\\/\\d+"), // Example: /files/123

// 47. Embedded identifiers in JSON responses
Pattern.compile("\\\"id\\\"\\s*:\\s*\\d+"), // Example: "id": 123

// 48. Query parameters with nested objects
Pattern.compile("query\\[\\'\\id\\'\\]\\s*:\\s*\\d+"), // Example: query['id']: 456

// 49. Session-specific IDs
Pattern.compile("session_id=\\d+"), // Example: ?session_id=789

// 50. Fallback object ID validation
Pattern.compile("fallback\\.id\\s*:\\s*\\d+"), // Example: fallback.id: 123
);

public static final List<Pattern> idorPatterns = Arrays.asList(
// 51. Path traversal with IDs
Pattern.compile("\\/\\w+\\/details\\/\\d+"), // Example: /user/details/123

// 52. Nested query string parameters
Pattern.compile("nested_query\\[id\\]=\\d+"), // Example: ?nested_query[id]=123

// 53. Unvalidated references in POST data
Pattern.compile("\"id\"\\s*:\\s*\\d+"), // Example: "id": 456

// 54. Resource ownership bypass
Pattern.compile("\\/resource\\/\\d+\\/access"), // Example: /resource/789/access

// 55. Object ID in nested JSON
Pattern.compile("\\\"objectId\\\"\\s*:\\s*\\d+"), // Example: "objectId": 123

// 56. Sensitive operations with direct IDs
Pattern.compile("\\/operation\\/\\d+"), // Example: /operation/456

// 57. File download paths with IDs
Pattern.compile("download\\?fileId=\\d+"), // Example: download?fileId=123

// 58. Legacy APIs with ID parameters
Pattern.compile("\\/api\\/v1\\/user\\/\\d+"), // Example: /api/v1/user/123

// 59. ID in RESTful POST endpoints
Pattern.compile("\\/api\\/\\w+\\/post\\/\\d+"), // Example: /api/orders/post/789

// 60. Secondary user IDs
Pattern.compile("\\\"secondaryUserId\\\"\\s*:\\s*\\d+"), // Example: "secondaryUserId": 654

// 61. Export functions with ID references
Pattern.compile("\\/export\\/\\d+"), // Example: /export/321

// 62. Logs referencing IDs
Pattern.compile("log_id=\\d+"), // Example: ?log_id=456

// 63. Admin-specific routes with IDs
Pattern.compile("\\/admin\\/user\\/\\d+"), // Example: /admin/user/123

// 64. Payment details with IDs
Pattern.compile("\\\"paymentId\\\"\\s*:\\s*\\d+"), // Example: "paymentId": 789

// 65. Nested API endpoints with IDs
Pattern.compile("\\/api\\/\\w+\\/\\d+\\/details"), // Example: /api/user/123/details

// 66. Inline ID destructuring
Pattern.compile("\\{\\s*id:\\s*\\d+\\s*\\}"), // Example: {id: 456}

// 67. Legacy URL parameters
Pattern.compile("legacy_id=\\d+"), // Example: ?legacy_id=789

// 68. Profile page IDs
Pattern.compile("\\/profile\\/details\\/\\d+"), // Example: /profile/details/123

// 69. Session-specific object IDs
Pattern.compile("sessionObjectId=\\d+"), // Example: ?sessionObjectId=456

// 70. Resource identifier query
Pattern.compile("resourceId=\\d+"), // Example: ?resourceId=789

// 71. API pagination with IDs
Pattern.compile("\\/api\\/\\w+\\/\\d+\\/page"), // Example: /api/posts/123/page

// 72. Hidden form fields with IDs
Pattern.compile("<input\\s+type=['\"]hidden['\"]\\s+name=['\"]id['\"]\\s+value=['\"]\\d+['\"]"), // Example: <input type="hidden" name="id" value="123">

// 73. Static resource identifiers
Pattern.compile("staticResourceId=\\d+"), // Example: ?staticResourceId=456

// 74. Batch operations with IDs
Pattern.compile("\\/batch\\/\\d+\\/process"), // Example: /batch/789/process

// 75. Transaction details with IDs
Pattern.compile("\\\"transactionId\\\"\\s*:\\s*\\d+"), // Example: "transactionId": 321

// 76. User tracking IDs
Pattern.compile("trackingId=\\d+"), // Example: ?trackingId=456

// 77. Query strings in complex URLs
Pattern.compile("\\?details=.*id=\\d+"), // Example: ?details=info&id=789

// 78. Resource fetch operations
Pattern.compile("fetchResource\\?id=\\d+"), // Example: fetchResource?id=123

// 79. Parent-child relationships in URLs
Pattern.compile("\\/parent\\/\\d+\\/child\\/\\d+"), // Example: /parent/123/child/456

// 80. Logs with embedded IDs
Pattern.compile("logDetails\\.id\\s*:\\s*\\d+"), // Example: logDetails.id: 789

// 81. URL-encoded ID values
Pattern.compile("%3Fid%3D\\d+"), // Example: %3Fid%3D123

// 82. API filters with IDs
Pattern.compile("filter=id:\\d+"), // Example: filter=id:456

// 83. Message references with IDs
Pattern.compile("\\/messages\\/\\d+\\/details"), // Example: /messages/789/details

// 84. Versioned API endpoints
Pattern.compile("\\/api\\/v\\d+\\/resource\\/\\d+"), // Example: /api/v2/resource/123

// 85. Inline resource IDs
Pattern.compile("\\\"resourceId\\\"\\s*:\\s*\\d+"), // Example: "resourceId": 456

// 86. User access tokens in headers
Pattern.compile("\\.headers\\[\"x-user-access-id\"]\\s*=\\s*\\d+"), // Example: req.headers["x-user-access-id"] = 123

// 87. Object-specific configurations
Pattern.compile("\\\"configId\\\"\\s*:\\s*\\d+"), // Example: "configId": 789

// 88. Bulk processing identifiers
Pattern.compile("\\/bulkProcess\\/\\d+"), // Example: /bulkProcess/123

// 89. Order details with IDs
Pattern.compile("orderDetails\\.id\\s*:\\s*\\d+"), // Example: orderDetails.id: 456

// 90. Nested JSON in logs
Pattern.compile("\\\"logDetails\\\"\\s*:\\s*\\{.*\"id\"\\s*:\\s*\\d+.*\\}"), // Example: {"logDetails": {"id": 789}}

// 91. Workflow identifiers
Pattern.compile("workflowId=\\d+"), // Example: ?workflowId=123

// 92. Chained resource paths
Pattern.compile("\\/resources\\/\\d+\\/next"), // Example: /resources/456/next

// 93. Debugging output with IDs
Pattern.compile("debugInfo\\.id=\\d+"), // Example: debugInfo.id=789

// 94. URL fragments with IDs
Pattern.compile("#resource\\/\\d+"), // Example: #resource/123

// 95. Legacy endpoints with IDs
Pattern.compile("\\/legacy\\/resource\\/\\d+"), // Example: /legacy/resource/456

// 96. Template rendering with IDs
Pattern.compile("\\/render\\/template\\/\\d+"), // Example: /render/template/789

// 97. ID in HTTP response headers
Pattern.compile("x-response-id:\\d+"), // Example: x-response-id: 123

// 98. Referenced object logs
Pattern.compile("referencedObject\\.id=\\d+"), // Example: referencedObject.id=456

// 99. API-specific payloads with IDs
Pattern.compile("payload\\.id\\s*:\\s*\\d+"), // Example: payload.id: 789

// 100. Unescaped ID references
Pattern.compile("\\/escaped\\/id\\/\\d+"), // Example: /escaped/id/123
);

public static final List<Pattern> rbacPatterns = Arrays.asList(
// 1. No role validation in REST endpoints
Pattern.compile("\\bapp\\.(get|post|put|delete)\\s*\\(.*\\)\\s*=>\\s*\\{.*\\}"), // Example: app.get('/route', ...)

// 2. Exposed sensitive admin routes without authorization
Pattern.compile("/admin/\\w+/settings"), // Example: /admin/user/settings

// 3. Direct access to sensitive resources
Pattern.compile("\\brouter\\.(get|post|put|delete)\\s*\\(\\s*['\"].*/admin/.*['\"]\\s*\\)"), // Example: router.get('/admin/settings')

// 4. Missing middleware for authorization
Pattern.compile("\\b(app|router)\\.use\\(.*\\)"), // Example: app.use('/secure-route')

// 5. Hardcoded admin role check
Pattern.compile("\\bif\\s*\\(.*role.*['\"]admin['\"]\\s*\\)"), // Example: if (role === 'admin')

// 6. Sensitive fetch or API calls without role validation
Pattern.compile("\\bfetch\\(.*\\)\\.then\\(.*\\)"), // Example: fetch('/secure-resource')

// 7. Exposed settings endpoints
Pattern.compile("/settings/(users|roles)"), // Example: /settings/users

// 8. Admin actions without role validation
Pattern.compile("\\bapp\\.(post|put|delete)\\s*\\(.*\\)"), // Example: app.post('/admin/action')

// 9. Database queries without validation
Pattern.compile("\\bdb\\.(find|insert|update|delete)\\s*\\(.*\\)"), // Example: db.find('users')

// 10. API endpoints missing role checks
Pattern.compile("\\brouter\\.(get|post|put|delete)\\s*\\(.*\\)"), // Example: router.get('/resource')

// 11. Role-based logic missing in conditionals
Pattern.compile("if\\s*\\(.*user\\.role.*\\)"), // Example: if (user.role)

// 12. Publicly exposed admin panels
Pattern.compile("<AdminPanel\\s*>"), // Example: <AdminPanel />

// 13. No conditional rendering for sensitive components
Pattern.compile("\\b(user\\.isAdmin|role\\s*==\\s*['\"]admin['\"])\\s*\\?"), // Example: user.isAdmin ? ...

// 14. Public endpoints with sensitive data
Pattern.compile("\\bapp\\.get\\(.*\\badmin\\b.*\\)"), // Example: app.get('/admin-data')

// 15. Static resources with sensitive access
Pattern.compile("/admin/static/\\w+"), // Example: /admin/static/settings

// 16. Missing RBAC enforcement on nested routes
Pattern.compile("/admin/\\w+/\\d+"), // Example: /admin/resource/123

// 17. Tokens hardcoded in headers
Pattern.compile("\\bheaders\\['authorization'\\]\\s*==\\s*['\"]Bearer .*['\"]"), // Example: headers['authorization'] == 'Bearer token'

// 18. Missing role checks in request handlers
Pattern.compile("req\\.user\\.role\\s*\\|\\|\\s*['\"]user['\"]"), // Example: req.user.role || 'user'

// 19. Missing conditional validation for sensitive resources
Pattern.compile("\\?role=admin"), // Example: /resource?role=admin

// 20. Exposed privileged data in responses
Pattern.compile("res\\.json\\(.*user\\.role.*\\)"), // Example: res.json({ user: { role: 'admin' } })

// 21. Hardcoded superuser bypasses
Pattern.compile("role\\s*:\\s*['\"]superuser['\"]"), // Example: role: 'superuser'

// 22. No validation on nested admin actions
Pattern.compile("/admin/action/\\w+"), // Example: /admin/action/delete

// 23. Public role assignment without restrictions
Pattern.compile("assignRole\\(.*['\"]admin['\"].*\\)"), // Example: assignRole(user, 'admin')

// 24. Missing authentication middleware for API endpoints
Pattern.compile("\\brouter\\.use\\(.*authMiddleware.*\\)"), // Example: router.use(authMiddleware)

// 25. Sensitive resource creation without role validation
Pattern.compile("\\bapp\\.post\\('/admin/create.*'\\)"), // Example: app.post('/admin/createUser')

// 26. Missing validation in resource editing
Pattern.compile("\\bapp\\.put\\('/admin/edit.*'\\)"), // Example: app.put('/admin/editUser')

// 27. Sensitive resource deletion without role checks
Pattern.compile("\\bapp\\.delete\\('/admin/delete.*'\\)"), // Example: app.delete('/admin/deleteUser')

// 28. Missing role checks for bulk operations
Pattern.compile("\\bapp\\.post\\('/admin/bulk.*'\\)"), // Example: app.post('/admin/bulkUpload')

// 29. Missing middleware for sensitive routes
Pattern.compile("\\b(app|router)\\.use\\('/secure.*'\\)"), // Example: app.use('/secureData')

// 30. Unrestricted access to sensitive dashboards
Pattern.compile("<Dashboard\\s*admin\\s*={.*true.*}>"), // Example: <Dashboard admin={true}>

// 31. Unvalidated session access
Pattern.compile("req\\.session\\.user\\.role\\s*\\|\\|\\s*['\"]user['\"]"), // Example: req.session.user.role || 'user'

// 32. Missing access control in API versioning
Pattern.compile("/api/v\\d+/admin/.*"), // Example: /api/v2/admin/data

// 33. Sensitive routes exposed in logs
Pattern.compile("console\\.log\\(.*['\"]admin['\"].*\\)"), // Example: console.log('admin access granted')

// 34. Missing role-based rendering in frontend
Pattern.compile("user\\.role\\s*!==\\s*['\"]admin['\"]"), // Example: user.role !== 'admin'

// 35. Missing authorization in dynamic routing
Pattern.compile("\\brouter\\.(get|post|put|delete)\\(.*['\"]/secure.*['\"].*\\)"), // Example: router.get('/secure-data')

// 36. Sensitive API calls in frontend without validation
Pattern.compile("axios\\.(get|post|put|delete)\\(.*['\"]/admin/.*['\"]"), // Example: axios.get('/admin/resource')

// 37. Missing middleware for sensitive frontend routes
Pattern.compile("<Route\\s*path=['\"]/admin/.*['\"]"), // Example: <Route path="/admin/dashboard">

// 38. Hardcoded privileged user IDs
Pattern.compile("userId\\s*:\\s*['\"]123['\"]"), // Example: userId: '123'

// 39. Missing role validation in conditional logic
Pattern.compile("if\\s*\\(\\s*user\\.role\\s*!==\\s*['\"]admin['\"]\\s*\\)"), // Example: if (user.role !== 'admin')

// 40. Exposed resource IDs without validation
Pattern.compile("req\\.params\\.id\\s*:\\s*\\d+"), // Example: req.params.id: 123

// 41. Static sensitive data in admin endpoints
Pattern.compile("/admin/static/(users|data)"), // Example: /admin/static/users

// 42. Missing admin role enforcement
Pattern.compile("user\\.role\\s*\\|\\|\\s*['\"]guest['\"]"), // Example: user.role || 'guest'

// 43. Public assignment of sensitive roles
Pattern.compile("assignRole\\(.*['\"]superuser['\"].*\\)"), // Example: assignRole(user, 'superuser')

// 44. Missing validation for nested admin objects
Pattern.compile("/admin/resource/\\d+/settings"), // Example: /admin/resource/123/settings

// 45. Admin privileges exposed in public endpoints
Pattern.compile("privilege\\s*:\\s*['\"]admin['\"]"), // Example: privilege: 'admin'

// 46. Missing authorization headers in requests
Pattern.compile("headers\\.authorization\\s*:\\s*undefined"), // Example: headers.authorization: undefined

// 47. Sensitive API without RBAC in middleware
Pattern.compile("app\\.use\\('/api/admin/.*',.*)"), // Example: app.use('/api/admin', ...)

// 48. Missing role validation on frontend buttons
Pattern.compile("<button\\s*onClick={.*admin.*}>"), // Example: <button onClick={navigateToAdmin}>

// 49. Hardcoded admin actions in logs
Pattern.compile("console\\.log\\(.*['\"]admin-action['\"].*\\)"), // Example: console.log('admin-action')

// 50. Missing admin restrictions in database queries
Pattern.compile("db\\.find\\(.*role\\s*:\\s*['\"]admin['\"]"), // Example: db.find({ role: 'admin' })
);

public static final List<Pattern> rbacPatterns = Arrays.asList(
// 51. Sensitive routes missing RBAC
Pattern.compile("/api/admin/(users|roles|settings)"), // Example: /api/admin/users

// 52. Direct calls to privileged actions without validation
Pattern.compile("\\bexecute\\(.*['\"]adminAction['\"].*\\)"), // Example: execute('adminAction')

// 53. Missing checks for sensitive POST requests
Pattern.compile("router\\.post\\(.*['\"]/admin/.*['\"].*\\)"), // Example: router.post('/admin/create')

// 54. Missing RBAC enforcement in GraphQL resolvers
Pattern.compile("resolver\\s*:\\s*\\{.*['\"]admin['\"].*\\}"), // Example: resolver: { admin: ... }

// 55. Sensitive resource updates without role checks
Pattern.compile("\\bapp\\.put\\(.*['\"]/secure/.*['\"].*\\)"), // Example: app.put('/secure/update')

// 56. Missing middleware for API resource groups
Pattern.compile("router\\.use\\(.*['\"]/api/secure/.*['\"].*\\)"), // Example: router.use('/api/secure')

// 57. Role bypass with wildcard routes
Pattern.compile("router\\.all\\(.*['\"]/.*['\"]\\)"), // Example: router.all('*', ...)

// 58. Hardcoded sensitive tokens in headers
Pattern.compile("\\bheaders\\['authorization'\\]\\s*:\\s*['\"]Bearer .*['\"]"), // Example: headers['authorization'] = 'Bearer staticToken'

// 59. Missing RBAC in file uploads
Pattern.compile("upload\\.single\\(.*['\"]adminFile['\"]\\)"), // Example: upload.single('adminFile')

// 60. No role-based validation for external integrations
Pattern.compile("axios\\.post\\(.*['\"]/admin/externalService['\"]\\)"), // Example: axios.post('/admin/externalService')

// 61. Lack of RBAC for analytics dashboards
Pattern.compile("/admin/analytics/\\w+"), // Example: /admin/analytics/reports

// 62. Missing admin checks in frontend pages
Pattern.compile("<Route\\s*path=['\"]/admin/.*['\"]\\s*component="), // Example: <Route path="/admin" component={AdminPage} />

// 63. Publicly accessible configuration routes
Pattern.compile("/admin/config/.*"), // Example: /admin/config/system

// 64. Role-based decisions missing for batch processing
Pattern.compile("batchProcess\\(.*role\\s*:\\s*['\"]admin['\"]"), // Example: batchProcess({ role: 'admin' })

// 65. Missing validations for sensitive file downloads
Pattern.compile("\\bapp\\.get\\(.*['\"]/admin/files/.*['\"]"), // Example: app.get('/admin/files/export')

// 66. No validation for privileged operations in services
Pattern.compile("performPrivilegedAction\\(.*['\"]admin['\"]\\)"), // Example: performPrivilegedAction('admin')

// 67. Role validation missing in WebSocket connections
Pattern.compile("ws\\.on\\(.*['\"]/admin/.*['\"]"), // Example: ws.on('/admin/socket')

// 68. Unrestricted access to backend API keys
Pattern.compile("req\\.headers\\.apiKey\\s*:\\s*undefined"), // Example: req.headers.apiKey: undefined

// 69. RBAC enforcement missing in mobile API
Pattern.compile("/mobile/api/admin/.*"), // Example: /mobile/api/admin/settings

// 70. Sensitive debug routes exposed
Pattern.compile("/debug/(admin|settings)"), // Example: /debug/admin/logs

// 71. Missing RBAC in GraphQL mutations
Pattern.compile("mutation\\s*:\\s*['\"]adminAction['\"]"), // Example: mutation: 'adminAction'

// 72. Missing validation for privileged API paths
Pattern.compile("\\brouter\\.post\\(.*['\"]/privileged/.*['\"]"), // Example: router.post('/privileged/action')

// 73. Hardcoded privileged user credentials in code
Pattern.compile("\\busername\\s*:\\s*['\"]admin['\"]"), // Example: username: 'admin'

// 74. Missing admin role validation for sensitive API payloads
Pattern.compile("req\\.body\\.role\\s*:\\s*['\"]admin['\"]"), // Example: req.body.role: 'admin'

// 75. Exposed admin-level REST endpoints
Pattern.compile("/api/v\\d+/admin/(create|update|delete)"), // Example: /api/v1/admin/create

// 76. No conditional rendering for admin-only elements
Pattern.compile("user\\.role\\s*!==\\s*['\"]admin['\"]\\s*\\?"), // Example: user.role !== 'admin' ? ...

// 77. Publicly accessible admin feature toggles
Pattern.compile("/features/admin/\\w+"), // Example: /features/admin/toggle

// 78. Missing RBAC in backend task schedulers
Pattern.compile("scheduleTask\\(.*['\"]adminTask['\"]"), // Example: scheduleTask('adminTask')

// 79. Unrestricted access to privileged modules
Pattern.compile("/modules/privileged/.*"), // Example: /modules/privileged/admin

// 80. Missing RBAC enforcement on backend logs
Pattern.compile("/logs/(admin|privileged)"), // Example: /logs/admin/errors

// 81. Admin-level routes missing authentication
Pattern.compile("\\brouter\\.get\\(.*['\"]/secure/admin/.*['\"]\\)"), // Example: router.get('/secure/admin')

// 82. Hardcoded privileged database queries
Pattern.compile("db\\.find\\(.*['\"]admin['\"]"), // Example: db.find({ role: 'admin' })

// 83. RBAC missing for external API integration
Pattern.compile("/admin/integrations/\\w+"), // Example: /admin/integrations/slack

// 84. Missing authorization in cloud service API
Pattern.compile("/cloud/admin/.*"), // Example: /cloud/admin/settings

// 85. Role validation missing in dynamic imports
Pattern.compile("import\\(.*['\"]/admin/.*['\"]\\)"), // Example: import('/admin/component')

// 86. Admin panels without RBAC checks
Pattern.compile("<AdminPanel\\s+.*\\/>"), // Example: <AdminPanel user={currentUser} />

// 87. Sensitive backend jobs exposed without validation
Pattern.compile("performJob\\(.*['\"]adminJob['\"]"), // Example: performJob('adminJob')

// 88. No validation in resource assignment APIs
Pattern.compile("assignResource\\(.*['\"]admin['\"]"), // Example: assignResource({ role: 'admin' })

// 89. RBAC missing in session-based actions
Pattern.compile("req\\.session\\.user\\.role\\s*:\\s*['\"]admin['\"]"), // Example: req.session.user.role: 'admin'

// 90. Sensitive resource rendering without restrictions
Pattern.compile("render\\(.*['\"]adminPage['\"]"), // Example: render('adminPage')

// 91. Exposed development routes for admin
Pattern.compile("/dev/(admin|settings)"), // Example: /dev/admin/debug

// 92. Missing RBAC for real-time admin data
Pattern.compile("/realtime/admin/.*"), // Example: /realtime/admin/stats

// 93. Missing RBAC for shared resources
Pattern.compile("/shared/admin/(files|resources)"), // Example: /shared/admin/files

// 94. Direct role assignment in frontend
Pattern.compile("setUserRole\\(.*['\"]admin['\"]"), // Example: setUserRole('admin')

// 95. No role-based checks in caching mechanisms
Pattern.compile("cache\\.get\\(.*['\"]admin['\"]"), // Example: cache.get('adminData')

// 96. Exposed internal API admin paths
Pattern.compile("/internal/admin/\\w+"), // Example: /internal/admin/config

// 97. Missing validation for session tokens
Pattern.compile("req\\.headers\\.authToken\\s*:\\s*undefined"), // Example: req.headers.authToken: undefined

// 98. Sensitive admin tasks in batch processors
Pattern.compile("batch\\.(create|update|delete)\\(.*['\"]admin['\"]"), // Example: batch.create({ role: 'admin' })

// 99. Missing RBAC enforcement in notifications
Pattern.compile("/admin/notifications/\\w+"), // Example: /admin/notifications/settings

// 100. Exposed admin endpoints in serverless functions
Pattern.compile("/functions/admin/.*"), // Example: /functions/admin/action
);

public static final List<Pattern> objectOwnershipPatterns = Arrays.asList(
// 1. Direct access to resources without ownership checks
Pattern.compile("\\bapp\\.(get|post|put|delete)\\(.*['\"]\\/resources\\/.*['\"].*\\)"), // Example: app.get('/resources/:id')

// 2. Missing validation for ownership in API handlers
Pattern.compile("\\b(req|request)\\.params\\.id\\s*:\\s*\\w+"), // Example: req.params.id

// 3. Direct database queries without ownership validation
Pattern.compile("\\bdb\\.(find|update|delete)\\(.*\\)"), // Example: db.find({ id: req.params.id })

// 4. Query parameters used without ownership validation
Pattern.compile("\\bquery\\.(id|userId|orderId)\\s*:\\s*req\\.(params|query)\\.id"), // Example: req.query.id

// 5. Missing ownership checks in fetch or API calls
Pattern.compile("fetch\\(.*['\"]\\/resources\\/\\d+['\"].*\\)"), // Example: fetch('/resources/123')

// 6. Resource updates without validating owner ID
Pattern.compile("\\.update\\(.*['\"]ownerId['\"].*\\)"), // Example: db.update({ ownerId: ... })

// 7. No ownership validation for sensitive operations
Pattern.compile("\\bperformAction\\(.*['\"]resourceId['\"].*\\)"), // Example: performAction({ resourceId: ... })

// 8. Ownership checks missing in middleware
Pattern.compile("router\\.use\\(.*['\"]\\/secure\\/.*['\"].*\\)"), // Example: router.use('/secure')

// 9. Hardcoded owner assignment without checks
Pattern.compile("\\bownerId\\s*:\\s*['\"]\\d+['\"]"), // Example: ownerId: '123'

// 10. Missing ownership checks for uploaded files
Pattern.compile("upload\\.single\\(.*['\"]file['\"]\\)"), // Example: upload.single('file')

// 11. Ownership checks bypassed in frontend validation
Pattern.compile("currentUser\\.id\\s*!==\\s*resource\\.ownerId"), // Example: currentUser.id !== resource.ownerId

// 12. Exposed routes for sensitive resources
Pattern.compile("\\brouter\\.get\\(.*['\"]\\/user\\/files\\/.*['\"]\\)"), // Example: router.get('/user/files/:id')

// 13. Missing ownership checks for document access
Pattern.compile("\\bdocument\\.getById\\(.*\\)"), // Example: document.getById(req.params.id)

// 14. No validation for user-created content
Pattern.compile("\\bcreateContent\\(.*['\"]owner['\"].*\\)"), // Example: createContent({ owner: ... })

// 15. Missing checks for API keys linked to ownership
Pattern.compile("\\bheaders\\.apiKey\\s*:\\s*req\\.headers\\.apiKey"), // Example: headers.apiKey: req.headers.apiKey

// 16. Object assignment without validation
Pattern.compile("\\bassignObject\\(.*['\"]userId['\"].*\\)"), // Example: assignObject({ userId: ... })

// 17. No ownership validation for shared resources
Pattern.compile("\\bshareResource\\(.*['\"]resourceId['\"].*\\)"), // Example: shareResource({ resourceId: ... })

// 18. Missing validation in GraphQL resolvers
Pattern.compile("\\bresolver\\s*:\\s*\\{.*\\['ownerId'\\].*\\}"), // Example: resolver: { ownerId: ... }

// 19. Missing ownership check for sensitive file access
Pattern.compile("\\bapp\\.get\\(.*['\"]\\/files\\/secure\\/.*['\"].*\\)"), // Example: app.get('/files/secure/:id')

// 20. Resource deletion without validating owner
Pattern.compile("\\bapp\\.delete\\(.*['\"]\\/resources\\/.*['\"].*\\)"), // Example: app.delete('/resources/:id')

// 21. Missing ownership checks in batch processes
Pattern.compile("batchProcess\\(.*['\"]owner['\"].*\\)"), // Example: batchProcess({ owner: ... })

// 22. Publicly exposed resource fetches
Pattern.compile("axios\\.get\\(.*['\"]\\/public\\/resources\\/.*['\"]\\)"), // Example: axios.get('/public/resources/:id')

// 23. Ownership validation bypass in REST APIs
Pattern.compile("\\brouter\\.post\\(.*['\"]\\/admin\\/resources\\/.*['\"]\\)"), // Example: router.post('/admin/resources')

// 24. Exposed debug routes with no ownership checks
Pattern.compile("/debug/(resources|ownership)"), // Example: /debug/resources

// 25. Missing validation in event-driven APIs
Pattern.compile("\\bevent\\.on\\(.*['\"]resourceUpdate['\"].*\\)"), // Example: event.on('resourceUpdate')

// 26. Ownership validation missing in WebSocket endpoints
Pattern.compile("ws\\.on\\(.*['\"]\\/resources\\/.*['\"]\\)"), // Example: ws.on('/resources/:id')

// 27. No validation for resource download permissions
Pattern.compile("downloadResource\\(.*['\"]ownerId['\"].*\\)"), // Example: downloadResource({ ownerId: ... })

// 28. Missing validation for sensitive audit logs
Pattern.compile("audit\\.log\\(.*['\"]owner['\"].*\\)"), // Example: audit.log({ owner: ... })

// 29. Exposed internal endpoints without checks
Pattern.compile("/internal/resources/(fetch|update)"), // Example: /internal/resources/fetch

// 30. Ownership checks bypassed in cache mechanisms
Pattern.compile("cache\\.get\\(.*['\"]resourceId['\"]\\)"), // Example: cache.get('resourceId')

// 31. Missing validation for admin-level resource operations
Pattern.compile("/admin/resources/(delete|modify)"), // Example: /admin/resources/delete

// 32. No ownership validation for session tokens
Pattern.compile("req\\.session\\.resourceId\\s*:\\s*req\\.params\\.id"), // Example: req.session.resourceId: req.params.id

// 33. Sensitive resource operations in background tasks
Pattern.compile("backgroundTask\\(.*['\"]resourceId['\"].*\\)"), // Example: backgroundTask({ resourceId: ... })

// 34. Ownership bypass in multi-user operations
Pattern.compile("assignToUser\\(.*['\"]resourceId['\"].*\\)"), // Example: assignToUser({ resourceId: ... })

// 35. Ownership validation missing for real-time updates
Pattern.compile("/realtime/resources/(update|delete)"), // Example: /realtime/resources/update

// 36. Missing ownership validation in serverless functions
Pattern.compile("/functions/resources/(fetch|modify)"), // Example: /functions/resources/fetch

// 37. Hardcoded owner assignments in APIs
Pattern.compile("\\bowner\\s*:\\s*['\"]\\d+['\"]"), // Example: owner: '123'

// 38. Missing ownership checks in import/export actions
Pattern.compile("exportResource\\(.*['\"]ownerId['\"].*\\)"), // Example: exportResource({ ownerId: ... })

// 39. Ownership bypass in admin panels
Pattern.compile("<AdminPanel\\s+.*\\/>"), // Example: <AdminPanel resourceId={...} />

// 40. Missing ownership checks in error handling routes
Pattern.compile("/errors/resources/(fetch|update)"), // Example: /errors/resources/fetch

// 41. Sensitive resource updates without owner validations
Pattern.compile("updateResource\\(.*['\"]ownerId['\"].*\\)"), // Example: updateResource({ ownerId: ... })

// 42. No validation for resource-related notifications
Pattern.compile("/notifications/resources/(fetch|update)"), // Example: /notifications/resources/fetch

// 43. Ownership checks bypassed in test routes
Pattern.compile("/test/resources/(fetch|modify)"), // Example: /test/resources/fetch

// 44. Ownership validation missing in API versioning
Pattern.compile("/api/v\\d+/resources/(fetch|modify)"), // Example: /api/v1/resources/fetch

// 45. Missing validation for deprecated resource routes
Pattern.compile("/deprecated/resources/(fetch|update)"), // Example: /deprecated/resources/fetch

// 46. No ownership checks for archived resources
Pattern.compile("/archive/resources/(fetch|delete)"), // Example: /archive/resources/fetch

// 47. Exposed ownership routes in legacy APIs
Pattern.compile("/legacy/resources/(fetch|modify)"), // Example: /legacy/resources/fetch

// 48. Missing ownership checks for version-controlled files
Pattern.compile("/versions/resources/(fetch|update)"), // Example: /versions/resources/fetch

// 49. Publicly exposed ownership operations
Pattern.compile("/public/resources/(fetch|update)"), // Example: /public/resources/fetch

// 50. Ownership validation missing in role-based endpoints
Pattern.compile("/role/(admin|user)/resources/(fetch|update)"), // Example: /role/admin/resources/fetch
);
public static final List<Pattern> objectOwnershipPatterns = Arrays.asList(
// 51. Ownership check missing in MongoDB queries
Pattern.compile("\\b(collection|db)\\.findOne\\(\\{\\s*_id:\\s*req\\.params\\.id\\s*\\}\\)"), // Example: collection.findOne({ _id: req.params.id })

// 52. No verification in file download endpoints
Pattern.compile("app\\.get\\(.*['\"]\\/download\\/.*['\"]\\)"), // Example: app.get('/download/:id')

// 53. Missing owner validation in Sequelize queries
Pattern.compile("sequelize\\.(findOne|update|destroy)\\(\\{\\s*where:\\s*\\{\\s*id:\\s*req\\.params\\.id\\s*\\}\\s*\\}\\)"), // Example: sequelize.findOne({ where: { id: req.params.id } })

// 54. Direct resource updates without owner checks
Pattern.compile("\\.update\\(\\{\\s*value:\\s*.*\\},\\s*\\{\\s*where:\\s*\\{\\s*id:\\s*req\\.params\\.id\\s*\\}\\s*\\}\\)"), // Example: db.update({ value: ... }, { where: { id: req.params.id } })

// 55. Missing validation for owner-specific routes
Pattern.compile("router\\.(get|post|put|delete)\\(.*['\"]\\/user\\/.*\\/settings\\/.*['\"]\\)"), // Example: router.get('/user/:id/settings')

// 56. Ownership check missing for GraphQL mutations
Pattern.compile("mutation\\s*\\w+\\s*\\(.*\\$id:\\s*ID!.*\\)\\s*\\{.*updateResource"), // Example: mutation updateResource($id: ID!)

// 57. No ownership validation for Stripe payments
Pattern.compile("stripe\\.charges\\.(create|retrieve)\\(.*\\)"), // Example: stripe.charges.create({...})

// 58. Ownership bypass in WebSocket message handlers
Pattern.compile("socket\\.on\\(.*['\"]\\/user\\/.*\\/messages['\"].*\\)"), // Example: socket.on('/user/messages')

// 59. Missing ownership validation for cloud storage
Pattern.compile("cloudStorage\\.getObject\\(.*['\"]userId['\"]:\\s*req\\.user\\.id.*\\)"), // Example: cloudStorage.getObject({ userId: ... })

// 60. Ownership validation missing for cascading deletes
Pattern.compile("db\\.delete\\(\\{\\s*resourceId:\\s*req\\.params\\.id\\s*\\}\\)"), // Example: db.delete({ resourceId: req.params.id })

// 61. No validation for owner in chained database queries
Pattern.compile("\\.find\\(.*\\)\\.populate\\(.*['\"]owner['\"].*\\)"), // Example: Resource.find(...).populate('owner')

// 62. Missing checks in chained API calls
Pattern.compile("axios\\.get\\(.*['\"]\\/resources\\/.*['\"]\\)\\.then\\(.*\\)"), // Example: axios.get('/resources/:id').then(...)

// 63. Exposed dynamic routes without ownership checks
Pattern.compile("router\\.get\\(.*['\"]\\/dynamic\\/.*['\"]\\)"), // Example: router.get('/dynamic/:resource')

// 64. Missing validation in background workers
Pattern.compile("worker\\.process\\(\\{\\s*resourceId:\\s*req\\.params\\.id\\s*\\}\\)"), // Example: worker.process({ resourceId: ... })

// 65. Ownership check missing in RESTful API generators
Pattern.compile("api\\.generate\\(.*['\"]\\/resources\\/.*['\"]\\)"), // Example: api.generate('/resources/:id')

// 66. No verification in Firebase database queries
Pattern.compile("firebase\\.database\\(\\).ref\\(.*['\"]\\/resources\\/.*['\"]\\)\\.once"), // Example: firebase.database().ref('/resources/:id').once(...)

// 67. Missing validation in upload handlers
Pattern.compile("multer\\.single\\(.*['\"]file['\"]\\)"), // Example: multer.single('file')

// 68. Ownership checks skipped in admin dashboards
Pattern.compile("<AdminDashboard\\s+.*\\/>"), // Example: <AdminDashboard resourceId={...} />

// 69. Missing ownership validation for audit logs
Pattern.compile("audit\\.log\\(.*['\"]resourceId['\"].*\\)"), // Example: audit.log({ resourceId: ... })

// 70. Hardcoded resource IDs bypassing ownership checks
Pattern.compile("\\bresourceId\\s*:\\s*['\"]\\d+['\"]"), // Example: resourceId: '123'

// 71. Missing owner validation in Redux actions
Pattern.compile("dispatch\\(\\{\\s*type:\\s*['\"]FETCH_RESOURCE['\"],\\s*id:\\s*req\\.params\\.id\\s*\\}\\)"), // Example: dispatch({ type: 'FETCH_RESOURCE', id: ... })

// 72. No validation for resource creation
Pattern.compile("createResource\\(\\{\\s*.*['\"]ownerId['\"].*\\}\\)"), // Example: createResource({ ownerId: ... })

// 73. Missing checks in search endpoints
Pattern.compile("app\\.post\\(.*['\"]\\/search\\/.*['\"]\\)"), // Example: app.post('/search')

// 74. Ownership bypass in event listeners
Pattern.compile("event\\.on\\(.*['\"]resourceUpdated['\"].*\\)"), // Example: event.on('resourceUpdated')

// 75. No validation in OAuth user scopes
Pattern.compile("\\boauth\\.getScopes\\(.*\\)"), // Example: oauth.getScopes(...)

// 76. Missing owner validation in GraphQL subscriptions
Pattern.compile("subscription\\s*\\w+\\s*\\(.*\\)\\s*\\{.*resourceUpdated"), // Example: subscription { resourceUpdated(...) }

// 77. Ownership bypass in Kafka message handlers
Pattern.compile("kafka\\.consume\\(.*['\"]resource_topic['\"].*\\)"), // Example: kafka.consume('resource_topic')

// 78. Missing checks for owner in URL query parameters
Pattern.compile("\\bquery\\.(id|ownerId)\\s*:\\s*req\\.query\\.(id|ownerId)"), // Example: req.query.id

// 79. Direct resource access in session handlers
Pattern.compile("session\\.get\\(.*['\"]resourceId['\"].*\\)"), // Example: session.get('resourceId')

// 80. Ownership validation skipped in error handling
Pattern.compile("errorHandler\\.log\\(.*['\"]resourceId['\"].*\\)"), // Example: errorHandler.log({ resourceId: ... })

// 81. Exposed owner-specific actions without checks
Pattern.compile("/actions/owner/(fetch|modify)"), // Example: /actions/owner/fetch

// 82. Missing checks in cron job scripts
Pattern.compile("cron\\.schedule\\(.*['\"]\\/tasks\\/.*['\"]\\)"), // Example: cron.schedule('/tasks/...')

// 83. Ownership validation missing in webhook handlers
Pattern.compile("webhook\\.on\\(.*['\"]\\/hooks\\/.*['\"]\\)"), // Example: webhook.on('/hooks/...')

// 84. Missing validation for paginated resources
Pattern.compile("paginate\\(.*['\"]ownerId['\"].*\\)"), // Example: paginate({ ownerId: ... })

// 85. Hardcoded user IDs bypassing validation
Pattern.compile("\\buserId\\s*:\\s*['\"]\\d+['\"]"), // Example: userId: '123'

// 86. Ownership bypass in shared resource management
Pattern.compile("shareResource\\(\\{\\s*.*\\}\\)"), // Example: shareResource(...)

// 87. Missing validation for multi-tenant databases
Pattern.compile("tenant\\.db\\(.*['\"]resources['\"]\\)"), // Example: tenant.db('resources')

// 88. No ownership validation for custom middlewares
Pattern.compile("middleware\\.use\\(.*['\"]/secure/.*['\"]\\)"), // Example: middleware.use('/secure')

// 89. Ownership validation skipped for archived data
Pattern.compile("/archive/(fetch|modify)"), // Example: /archive/fetch

// 90. Missing checks in mobile-specific APIs
Pattern.compile("/mobile/resources/(fetch|delete)"), // Example: /mobile/resources/fetch

// 91. Exposed legacy API endpoints
Pattern.compile("/legacy/resources/(update|delete)"), // Example: /legacy/resources/update

// 92. Missing validation for cloud functions
Pattern.compile("cloudFunction\\.invoke\\(.*['\"]resourceId['\"]\\)"), // Example: cloudFunction.invoke({ resourceId: ... })

// 93. Ownership bypass in unit tests
Pattern.compile("test\\(.*['\"]\\/resources\\/.*['\"]\\)"), // Example: test('/resources/:id')

// 94. Ownership validation missing in staging environments
Pattern.compile("/staging/resources/(fetch|modify)"), // Example: /staging/resources/fetch

// 95. Missing validation for sandboxed operations
Pattern.compile("/sandbox/resources/(fetch|update)"), // Example: /sandbox/resources/fetch

// 96. Ownership checks bypassed in trial accounts
Pattern.compile("/trial/resources/(fetch|delete)"), // Example: /trial/resources/fetch

// 97. No validation for pre-release endpoints
Pattern.compile("/beta/resources/(fetch|modify)"), // Example: /beta/resources/fetch

// 98. Ownership checks missing in custom GraphQL resolvers
Pattern.compile("resolver\\(.*['\"]ownerId['\"].*\\)"), // Example: resolver({ ownerId: ... })

// 99. Missing validation in third-party integrations
Pattern.compile("thirdParty\\.api\\(.*['\"]resourceId['\"].*\\)"), // Example: thirdParty.api({ resourceId: ... })

// 100. Exposed debug endpoints with no ownership validation
Pattern.compile("/debug/resources/(fetch|update)"), // Example: /debug/resources/fetch
);
public static final List<Pattern> middlewareDecoratorPatterns = Arrays.asList(
// 1. Missing middleware in Express route definitions
Pattern.compile("\\bapp\\.(get|post|put|delete)\\s*\\(\\s*['\"].*['\"],\\s*function\\s*\\("),

// 2. Direct route handling without middleware
Pattern.compile("router\\.(get|post|put|delete)\\s*\\(\\s*['\"].*['\"],\\s*async\\s*\\("),

// 3. Skipping middleware in route chaining
Pattern.compile("\\.use\\(.*['\"]\\/api\\/.*['\"]\\).*\\.route\\(.*['\"]\\/.*['\"]\\)\\.get\\("),

// 4. No middleware applied for sensitive admin routes
Pattern.compile("app\\.use\\(['\"]\\/admin['\"],\\s*\\w*\\)"), // Example: app.use('/admin', ...)

// 5. Routes defined without decorator or middleware
Pattern.compile("\\@Controller\\(['\"].*['\"]\\)\\s*\\@Get\\(['\"].*['\"]\\)"), // Example: @Controller('/users') @Get('/profile')

// 6. Middleware bypassed for WebSocket handlers
Pattern.compile("socket\\.on\\(['\"].*['\"],\\s*async\\s*\\("),

// 7. Missing centralized middleware in API routes
Pattern.compile("app\\.all\\(['\"].*['\"],\\s*async\\s*\\("),

// 8. Missing middleware for batch processing endpoints
Pattern.compile("router\\.(get|post|put|delete)\\(.*['\"]\\/batch\\/.*['\"],\\s*\\w*\\)"),

// 9. Skipped middleware in GraphQL resolvers
Pattern.compile("resolver\\(.*\\)\\s*=>\\s*\\{.*\\}"), // Example: resolver(() => {...})

// 10. No decorators used for NestJS route guards
Pattern.compile("\\@UseGuards\\(\\s*\\)"), // Example: @UseGuards()

// 11. Middleware skipped for paginated data
Pattern.compile("router\\.(get|post)\\(['\"].*\\/page\\/.*['\"],\\s*async\\s*\\("),

// 12. Missing decorator for protecting RESTful routes
Pattern.compile("\\@RestController\\(['\"].*['\"]\\)\\s*\\@Put\\(['\"].*['\"]\\)"), // Example: @RestController('/items') @Put('/update')

// 13. Middleware bypass for CRUD operations
Pattern.compile("\\brouter\\.(post|put|delete)\\(['\"].*\\/create\\/.*['\"],\\s*\\w*\\)"),

// 14. Missing centralized middleware in chained routes
Pattern.compile("\\.route\\(['\"].*['\"]\\)\\.post\\("),

// 15. Decorator missing in custom endpoints
Pattern.compile("\\@CustomEndpoint\\(\\{.*\\}\\)"), // Example: @CustomEndpoint({})

// 16. No middleware in async routes
Pattern.compile("async\\s*function\\s*\\w+\\s*\\(\\s*req,\\s*res,\\s*next\\s*\\)"),

// 17. Middleware skipped for file uploads
Pattern.compile("app\\.post\\(['\"]\\/upload['\"],\\s*\\w*\\)"), // Example: app.post('/upload', ...)

// 18. No decorator for API gateway handlers
Pattern.compile("\\@Gateway\\(['\"].*['\"]\\)\\s*\\@Post\\(['\"].*['\"]\\)"), // Example: @Gateway('/api') @Post('/process')

// 19. Middleware bypassed in chained query handlers
Pattern.compile("\\.route\\(\\)\\.put\\(\\)"), // Example: app.route(...).put(...)

// 20. Missing middleware for multi-tenant routes
Pattern.compile("app\\.use\\(['\"]\\/tenants['\"],\\s*\\w*\\)"), // Example: app.use('/tenants', ...)

// 21. Middleware skipped for event-driven APIs
Pattern.compile("event\\.on\\(['\"].*['\"],\\s*\\w*\\)"), // Example: event.on(...)

// 22. No middleware for role-based routes
Pattern.compile("app\\.get\\(['\"]\\/roles\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/roles/:id', ...)

// 23. Missing centralized middleware for resource validation
Pattern.compile("router\\.(get|post|put|delete)\\(['\"].*\\/resource\\/.*['\"],\\s*\\w*\\)"),

// 24. Middleware skipped for federated login
Pattern.compile("app\\.post\\(['\"]\\/auth\\/federated['\"],\\s*\\w*\\)"), // Example: app.post('/auth/federated', ...)

// 25. No decorator for GraphQL subscriptions
Pattern.compile("\\@Subscription\\(['\"].*['\"]\\)"), // Example: @Subscription(...)

// 26. Middleware missing for transactional APIs
Pattern.compile("app\\.use\\(['\"]\\/transaction\\/.*['\"],\\s*\\w*\\)"),

// 27. Middleware skipped for OAuth callbacks
Pattern.compile("app\\.get\\(['\"]\\/oauth\\/callback['\"],\\s*\\w*\\)"), // Example: app.get('/oauth/callback', ...)

// 28. Middleware missing for webhook handlers
Pattern.compile("router\\.(post|put)\\(['\"]\\/webhook\\/.*['\"],\\s*\\w*\\)"),

// 29. Middleware bypass for GraphQL queries
Pattern.compile("query\\s*\\w+\\s*\\{.*\\}"), // Example: query {...}

// 30. Missing middleware for email processing
Pattern.compile("app\\.post\\(['\"]\\/email\\/send['\"],\\s*\\w*\\)"), // Example: app.post('/email/send', ...)

// 31. No decorator for access control in NestJS
Pattern.compile("\\@Roles\\(\\s*\\)"), // Example: @Roles()

// 32. Middleware skipped for API documentation routes
Pattern.compile("app\\.get\\(['\"]\\/docs\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/docs/api', ...)

// 33. No middleware in real-time chat handlers
Pattern.compile("socket\\.on\\(['\"]\\/chat\\/.*['\"],\\s*\\w*\\)"), // Example: socket.on('/chat', ...)

// 34. Missing centralized middleware in routing modules
Pattern.compile("app\\.module\\(['\"]\\/routes\\/.*['\"],\\s*\\w*\\)"),

// 35. Middleware skipped for configuration endpoints
Pattern.compile("app\\.post\\(['\"]\\/config\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/config/update', ...)

// 36. Missing middleware for API key validation
Pattern.compile("router\\.(get|post)\\(['\"]\\/apikey\\/.*['\"],\\s*\\w*\\)"),

// 37. Middleware bypassed for feature toggles
Pattern.compile("app\\.get\\(['\"]\\/features\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/features/:id', ...)

// 38. No decorator in event subscription
Pattern.compile("\\@Subscribe\\(['\"].*['\"]\\)"), // Example: @Subscribe(...)

// 39. Missing middleware in dynamic imports
Pattern.compile("\\.then\\(\\s*module\\s*=>\\s*module\\.default\\)"), // Example: import(...).then(module => module.default)

// 40. Middleware skipped for user preference endpoints
Pattern.compile("router\\.(get|post)\\(['\"]\\/preferences\\/.*['\"],\\s*\\w*\\)"),

// 41. Middleware missing for analytics endpoints
Pattern.compile("app\\.post\\(['\"]\\/analytics\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/analytics/upload', ...)

// 42. Missing decorator for GraphQL mutations
Pattern.compile("\\@Mutation\\(['\"].*['\"]\\)"), // Example: @Mutation(...)

// 43. Middleware skipped for audit logs
Pattern.compile("app\\.post\\(['\"]\\/audit\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/audit/log', ...)

// 44. No middleware for scheduled tasks
Pattern.compile("app\\.post\\(['\"]\\/tasks\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/tasks/create', ...)

// 45. Middleware bypassed for CDN routes
Pattern.compile("router\\.get\\(['\"]\\/cdn\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/cdn/:id', ...)

// 46. Missing centralized middleware in load balancers
Pattern.compile("app\\.use\\(['\"]\\/balancer\\/.*['\"],\\s*\\w*\\)"),

// 47. Middleware missing for shared resources
Pattern.compile("router\\.get\\(['\"]\\/shared\\/.*['\"],\\s*\\w*\\)"),

// 48. Middleware skipped for testing environments
Pattern.compile("app\\.post\\(['\"]\\/test\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/test/api', ...)

// 49. Missing decorators for rate limiting
Pattern.compile("\\@RateLimit\\(['\"].*['\"]\\)"), // Example: @RateLimit(...)

// 50. Middleware bypassed for service-specific endpoints
Pattern.compile("router\\.(get|post)\\(['\"]\\/services\\/.*['\"],\\s*\\w*\\)"),
);

public static final List<Pattern> middlewareDecoratorPatternsExtended = Arrays.asList(

// 51. Middleware bypassed for admin API routes
Pattern.compile("\\brouter\\.get\\(['\"]\\/admin\\/api\\/.*['\"],\\s*\\w*\\)"),

// 52. Missing middleware for user profile endpoints
Pattern.compile("app\\.get\\(['\"]\\/users\\/profile\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/users/profile', ...)

// 53. Skipped middleware for file download routes
Pattern.compile("router\\.get\\(['\"]\\/download\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/download/:fileId', ...)

// 54. Missing middleware for report generation
Pattern.compile("app\\.post\\(['\"]\\/reports\\/generate\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/reports/generate', ...)

// 55. Middleware skipped for versioned APIs
Pattern.compile("app\\.use\\(['\"]\\/api\\/v\\d+\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/api/v1', ...)

// 56. No middleware for API token validation
Pattern.compile("router\\.(get|post)\\(['\"]\\/token\\/validate['\"],\\s*\\w*\\)"),

// 57. Missing centralized middleware for project-specific routes
Pattern.compile("app\\.use\\(['\"]\\/projects\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/projects/:id', ...)

// 58. Middleware bypassed for shopping cart actions
Pattern.compile("router\\.post\\(['\"]\\/cart\\/add['\"],\\s*\\w*\\)"), // Example: router.post('/cart/add', ...)

// 59. Missing middleware for subscription plans
Pattern.compile("app\\.get\\(['\"]\\/subscriptions\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/subscriptions/:id', ...)

// 60. Middleware skipped for notifications
Pattern.compile("router\\.post\\(['\"]\\/notifications\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/notifications/send', ...)

// 61. Missing decorator for GraphQL mutations with sensitive data
Pattern.compile("\\@Mutation\\(['\"].*['\"]\\)\\s*\\{.*\\}"), // Example: @Mutation(...)

// 62. Middleware skipped for financial transactions
Pattern.compile("app\\.post\\(['\"]\\/transactions\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/transactions/transfer', ...)

// 63. No middleware for data import/export endpoints
Pattern.compile("router\\.(post|get)\\(['\"]\\/data\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/data/export', ...)

// 64. Middleware bypassed for system settings
Pattern.compile("app\\.put\\(['\"]\\/settings\\/.*['\"],\\s*\\w*\\)"), // Example: app.put('/settings/update', ...)

// 65. Missing centralized middleware for tenant-based APIs
Pattern.compile("app\\.use\\(['\"]\\/tenant\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/tenant/:id', ...)

// 66. Middleware skipped for feedback submission
Pattern.compile("router\\.post\\(['\"]\\/feedback\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/feedback/submit', ...)

// 67. Missing middleware for custom endpoints
Pattern.compile("app\\.use\\(['\"]\\/custom\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/custom/feature', ...)

// 68. Middleware bypassed for audit trails
Pattern.compile("router\\.post\\(['\"]\\/audit\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/audit/log', ...)

// 69. Missing decorators for multi-tenant role validation
Pattern.compile("\\@Roles\\(['\"].*['\"]\\)"), // Example: @Roles(...)

// 70. Middleware skipped for multi-step forms
Pattern.compile("router\\.get\\(['\"]\\/form\\/step\\d+\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/form/step1', ...)

// 71. No middleware for event notifications
Pattern.compile("app\\.post\\(['\"]\\/events\\/notify['\"],\\s*\\w*\\)"), // Example: app.post('/events/notify', ...)

// 72. Middleware bypassed for user preferences
Pattern.compile("router\\.put\\(['\"]\\/preferences\\/.*['\"],\\s*\\w*\\)"), // Example: router.put('/preferences/update', ...)

// 73. Missing centralized middleware for real-time updates
Pattern.compile("socket\\.on\\(['\"]\\/updates\\/.*['\"],\\s*\\w*\\)"), // Example: socket.on('/updates', ...)

// 74. Middleware skipped for file uploads
Pattern.compile("app\\.post\\(['\"]\\/upload\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/upload/file', ...)

// 75. No middleware for cache management
Pattern.compile("router\\.post\\(['\"]\\/cache\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/cache/clear', ...)

// 76. Middleware bypassed for service integrations
Pattern.compile("app\\.use\\(['\"]\\/integrations\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/integrations/:service', ...)

// 77. Missing decorators for GraphQL subscriptions
Pattern.compile("\\@Subscription\\(['\"].*['\"]\\)\\s*\\{.*\\}"), // Example: @Subscription(...)

// 78. Middleware skipped for analytics endpoints
Pattern.compile("router\\.post\\(['\"]\\/analytics\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/analytics/upload', ...)

// 79. No middleware for order management
Pattern.compile("app\\.get\\(['\"]\\/orders\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/orders/:id', ...)

// 80. Middleware bypassed for webhook endpoints
Pattern.compile("router\\.(post|get)\\(['\"]\\/webhook\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/webhook/receive', ...)

// 81. Missing middleware for background tasks
Pattern.compile("app\\.post\\(['\"]\\/tasks\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/tasks/create', ...)

// 82. Middleware skipped for user authentication
Pattern.compile("router\\.post\\(['\"]\\/auth\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/auth/login', ...)

// 83. Missing centralized middleware for resource access
Pattern.compile("app\\.use\\(['\"]\\/resources\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/resources/:id', ...)

// 84. Middleware bypassed for system-level operations
Pattern.compile("router\\.post\\(['\"]\\/system\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/system/restart', ...)

// 85. Missing middleware for IoT device endpoints
Pattern.compile("router\\.(get|post)\\(['\"]\\/devices\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/devices/status', ...)

// 86. Middleware skipped for payment gateways
Pattern.compile("app\\.post\\(['\"]\\/payments\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/payments/process', ...)

// 87. No middleware for partner integrations
Pattern.compile("router\\.use\\(['\"]\\/partners\\/.*['\"],\\s*\\w*\\)"), // Example: router.use('/partners/:id', ...)

// 88. Middleware bypassed for customer portals
Pattern.compile("app\\.get\\(['\"]\\/portal\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/portal/dashboard', ...)

// 89. Missing middleware for localized endpoints
Pattern.compile("router\\.(get|post)\\(['\"]\\/locale\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/locale/settings', ...)

// 90. Middleware skipped for debugging endpoints
Pattern.compile("app\\.get\\(['\"]\\/debug\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/debug/logs', ...)

// 91. Missing decorators for protected API gateway routes
Pattern.compile("\\@Api\\(['\"].*['\"]\\)"), // Example: @Api(...)

// 92. Middleware bypassed for mobile app-specific endpoints
Pattern.compile("router\\.post\\(['\"]\\/mobile\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/mobile/push', ...)

// 93. Missing middleware for resource exports
Pattern.compile("app\\.post\\(['\"]\\/exports\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/exports/download', ...)

// 94. Middleware skipped for archived data
Pattern.compile("router\\.get\\(['\"]\\/archives\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/archives/view', ...)

// 95. No middleware for search functionality
Pattern.compile("app\\.get\\(['\"]\\/search\\/.*['\"],\\s*\\w*\\)"), // Example: app.get('/search/query', ...)

// 96. Middleware bypassed for API metrics
Pattern.compile("router\\.get\\(['\"]\\/metrics\\/.*['\"],\\s*\\w*\\)"), // Example: router.get('/metrics/system', ...)

// 97. Missing middleware for dependency injections
Pattern.compile("app\\.use\\(['\"]\\/di\\/.*['\"],\\s*\\w*\\)"), // Example: app.use('/di/service', ...)

// 98. Middleware skipped for team collaboration endpoints
Pattern.compile("router\\.post\\(['\"]\\/teams\\/.*['\"],\\s*\\w*\\)"), // Example: router.post('/teams/create', ...)

// 99. Missing middleware for SSO authentication
Pattern.compile("app\\.post\\(['\"]\\/sso\\/.*['\"],\\s*\\w*\\)"), // Example: app.post('/sso/login', ...)

// 100. Middleware bypassed for restricted settings
Pattern.compile("router\\.put\\(['\"]\\/restricted\\/.*['\"],\\s*\\w*\\)"), // Example: router.put('/restricted/update', ...)

);


