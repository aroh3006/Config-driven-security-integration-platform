"""Field lists copied from vendor OpenAPI specs, read on 2026-10-31.

GitHub: github/rest-api-description, descriptions/api.github.com/api.github.com.json
Okta: okta/okta-management-openapi-spec, dist/current/management-minimal.yaml
Jira: developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json

OKTA_LOG_FIELDS also lists device and gatewayContext, seen in a real /api/v1/logs response.
"""

GITHUB_ALERT_REQUIRED = {
    "created_at", "dependency", "dismissed_at", "dismissed_by", "dismissed_comment", "dismissed_reason",
    "fixed_at", "html_url", "number", "security_advisory", "security_vulnerability", "state", "updated_at", "url",
}
GITHUB_ALERT_FIELDS = GITHUB_ALERT_REQUIRED | {"assignees", "auto_dismissed_at", "dismissal_request", "reachability"}
GITHUB_ALERT_STATES = {"auto_dismissed", "dismissed", "fixed", "open"}
GITHUB_ADVISORY_REQUIRED = {
    "cve_id", "cvss", "cwes", "description", "ghsa_id", "identifiers", "published_at", "references",
    "severity", "summary", "updated_at", "vulnerabilities", "withdrawn_at",
}
GITHUB_ADVISORY_FIELDS = GITHUB_ADVISORY_REQUIRED | {"classification", "cvss_severities", "epss"}
GITHUB_ADVISORY_SEVERITIES = {"low", "medium", "high", "critical"}
GITHUB_VULNERABILITY_FIELDS = {"first_patched_version", "package", "severity", "vulnerable_version_range"}
GITHUB_USER_REQUIRED = {
    "avatar_url", "events_url", "followers_url", "following_url", "gists_url", "gravatar_id", "html_url", "id",
    "login", "node_id", "organizations_url", "received_events_url", "repos_url", "site_admin", "starred_url",
    "subscriptions_url", "type", "url",
}
GITHUB_USER_FIELDS = GITHUB_USER_REQUIRED | {"email", "name", "starred_at", "user_view_type"}

OKTA_LOG_FIELDS = {
    "actor", "authenticationContext", "client", "debugContext", "device", "displayMessage", "eventType",
    "gatewayContext", "legacyEventType", "outcome", "published", "request", "securityContext", "severity", "target",
    "transaction", "uuid", "version",
}
OKTA_ACTOR_FIELDS = {"alternateId", "detailEntry", "displayName", "id", "type"}
OKTA_CLIENT_FIELDS = {"device", "geographicalContext", "id", "ipAddress", "userAgent", "zone"}
OKTA_SECURITY_FIELDS = {
    "asNumber", "asOrg", "botProtection", "domain", "ipDetails", "isProxy", "isp", "risk", "tlsFingerprint",
    "userBehaviors",
}
OKTA_SEVERITIES = {"DEBUG", "ERROR", "INFO", "WARN"}
OKTA_USER_FIELDS = {
    "_embedded", "_links", "activated", "created", "credentials", "id", "lastLogin", "lastUpdated",
    "passwordChanged", "profile", "realmId", "status", "statusChanged", "transitioningToStatus", "type",
}
OKTA_USER_STATUSES = {
    "ACTIVE", "DEPROVISIONED", "LOCKED_OUT", "PASSWORD_EXPIRED", "PROVISIONED", "RECOVERY", "STAGED", "SUSPENDED",
}
OKTA_ERROR_FIELDS = {"errorCauses", "errorCode", "errorId", "errorLink", "errorSummary"}

JIRA_RESULT_FIELDS = {"isLast", "issues", "names", "nextPageToken", "schema", "warnings"}
JIRA_ISSUE_FIELDS = {
    "changelog", "editmeta", "expand", "fields", "fieldsToInclude", "id", "key", "names", "operations",
    "properties", "renderedFields", "schema", "self", "transitions", "versionedRepresentations",
}
JIRA_ERROR_FIELDS = {"errorMessages", "errors", "status"}
