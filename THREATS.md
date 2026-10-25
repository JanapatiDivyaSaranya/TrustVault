# Threat Model & Security Considerations - TrustVault

## 1. Identified Threats

### Threat 1: Unauthorized Document Access (Broken Object Level Authorization - BOLA)
- **Risk:** User attempting to view or download a document belonging to another user without permissions.
- **Mitigation:** Backend checks verify if `current_user.id` is the document owner, has explicit shared permission, or has `admin` role before serving any file.

### Threat 2: Unrestricted File Upload
- **Risk:** Attacker uploading malicious executable files (`.exe`, `.php`, `.sh`).
- **Mitigation:** `secure_filename()` sanitization and strict validation on file extensions.

### Threat 3: Privilege Escalation
- **Risk:** Regular users executing administrative tasks or accessing system audit logs.
- **Mitigation:** Server-side role checks (`if current_user.role != 'admin'`) returning access error status.

### Threat 4: SQL Injection & Authentication Bypass
- **Risk:** Manipulating login inputs to bypass authentication.
- **Mitigation:** SQLAlchemy ORM parameterized queries and Werkzeug password hashing.