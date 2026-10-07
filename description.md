A stored cross-site scripting vulnerability has been confirmed in mathurvishal CloudClassroom-PHP-Project at commit `5dadec098bfbbf3300d60c3494db3fb95b66e7be`. The affected endpoint is `manageassessment2.php`, and the affected POST parameters are `ExamName`, `Q1`, `Q2`, `Q3`, `Q4`, and `Q5`.

The endpoint redirects unauthenticated requests to the faculty login page but does not terminate PHP execution. Consequently, an unauthenticated attacker can still reach the assessment update routine and persist attacker-controlled content. The stored fields are later rendered without context-appropriate HTML encoding in `manageassessment2.php`; question fields are also rendered to students by `takeassessment2.php`.

The issue was reproduced in an isolated local environment. A POST containing `</textarea><svg onload=alert(document.domain)>` in `ExamName` received an HTTP 302 response but updated the database. A subsequent response contained an executable `svg[onload]` element, and an authenticated Firefox session displayed `127.0.0.1` from `document.domain`, confirming JavaScript execution in the application's origin.

The vulnerability is classified as CWE-79. Suggested CVSS v3.1 is 6.1: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`. The confirmed affected commit is the repository's current `master` commit. No fixed commit or release was identified during the October 6, 2026 review.

Recommended remediation is to terminate execution with `exit` immediately after failed authentication checks, enforce server-side authorization before assessment updates, use prepared SQL statements, and encode all database values for their HTML output context with `htmlspecialchars(..., ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`.

Researchers:

- Marcus Chaves — `vinniboy021@gmail.com`
- Fernando Viana — `nanduviana@gmail.com`
