import 'dart:io';
import 'package:xml/xml.dart';

// ─────────────────────────────────────────────
// Data models
// ─────────────────────────────────────────────

class ApiConfig {
  final String baseUrl;
  final String apiKey;
  final int timeout;

  ApiConfig({
    required this.baseUrl,
    required this.apiKey,
    required this.timeout,
  });
}

class UserConfig {
  final String id;
  final String role;
  final String name;
  final String email;

  UserConfig({
    required this.id,
    required this.role,
    required this.name,
    required this.email,
  });
}

class FirewallRule {
  final String action;
  final String ip;

  FirewallRule({required this.action, required this.ip});
}

class ValidationResult {
  final List<String> errors;
  final List<String> warnings;

  ValidationResult({required this.errors, required this.warnings});

  bool get isValid => errors.isEmpty;
}

// ─────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────

class AppConfigParser {
  final XmlDocument _document;

  AppConfigParser(String xmlContent)
      : _document = XmlDocument.parse(xmlContent);

  /// Parse API configuration block
  ApiConfig parseApiConfig() {
    final api = _document.findAllElements('api').first;

    final baseUrl = api.findElements('baseUrl').first.innerText.trim();
    final apiKey = api.findElements('apiKey').first.innerText.trim();
    final timeoutStr = api.findElements('timeout').first.innerText.trim();
    final timeout = int.tryParse(timeoutStr) ?? -1;

    return ApiConfig(baseUrl: baseUrl, apiKey: apiKey, timeout: timeout);
  }

  /// Parse all user elements
  List<UserConfig> parseUsers() {
    return _document.findAllElements('user').map((userElement) {
      final id = userElement.getAttribute('id') ?? '';
      final role = userElement.getAttribute('role') ?? '';
      final name = userElement.findElements('name').first.innerText.trim();
      final email = userElement.findElements('email').first.innerText.trim();

      return UserConfig(id: id, role: role, name: name, email: email);
    }).toList();
  }

  /// Parse firewall rules
  List<FirewallRule> parseFirewallRules() {
    return _document.findAllElements('rule').map((ruleElement) {
      final action = ruleElement.getAttribute('action') ?? '';
      final ip = ruleElement.getAttribute('ip') ?? '';
      return FirewallRule(action: action, ip: ip);
    }).toList();
  }
}

// ─────────────────────────────────────────────
// Validator
// ─────────────────────────────────────────────

class AppConfigValidator {
  final List<String> _errors = [];
  final List<String> _warnings = [];

  ValidationResult validate({
    required ApiConfig apiConfig,
    required List<UserConfig> users,
    required List<FirewallRule> firewallRules,
  }) {
    _errors.clear();
    _warnings.clear();

    _validateApiConfig(apiConfig);
    _validateUsers(users);
    _validateFirewallRules(firewallRules);

    return ValidationResult(errors: List.from(_errors), warnings: List.from(_warnings));
  }

  // ── API config checks ──────────────────────

  void _validateApiConfig(ApiConfig config) {
    // 1. apiKey must not be empty
    if (config.apiKey.isEmpty) {
      _errors.add('[API] apiKey must not be empty.');
    } else {
      // Warn if key looks like a placeholder
      if (config.apiKey.contains('REPLACE') ||
          config.apiKey.contains('YOUR_KEY') ||
          config.apiKey == 'ABCD1234-EFGH5678-IJKL9101') {
        _warnings.add(
            '[API] apiKey appears to be a placeholder value. Replace it with a real key stored securely.');
      }
    }

    // 2. timeout must be between 10 and 60 seconds
    if (config.timeout < 10 || config.timeout > 60) {
      _errors.add(
          '[API] timeout value (${config.timeout}s) is out of the acceptable range [10–60].');
    }

    // 3. baseUrl must use HTTPS
    if (!config.baseUrl.startsWith('https://')) {
      _errors.add('[API] baseUrl must use HTTPS. Found: ${config.baseUrl}');
    }
  }

  // ── User checks ───────────────────────────

  void _validateUsers(List<UserConfig> users) {
    // 4. All user IDs must be unique
    final seenIds = <String>{};
    for (final user in users) {
      if (user.id.isEmpty) {
        _errors.add('[Users] A user element is missing its id attribute.');
      } else if (seenIds.contains(user.id)) {
        _errors.add('[Users] Duplicate user id found: "${user.id}".');
      } else {
        seenIds.add(user.id);
      }

      // Warn about plain-text email storage
      if (user.email.isNotEmpty) {
        _warnings.add(
            '[Users] User "${user.id}" stores email in plain text ("${user.email}"). '
            'Consider using a hashed identifier instead.');
      }
    }
  }

  // ── Firewall checks ───────────────────────

  void _validateFirewallRules(List<FirewallRule> rules) {
    const validActions = {'allow', 'deny'};

    for (int i = 0; i < rules.length; i++) {
      final rule = rules[i];

      // 5. Action must be 'allow' or 'deny'
      if (!validActions.contains(rule.action.toLowerCase())) {
        _errors.add(
            '[Firewall] Rule #$i has invalid action "${rule.action}". Must be "allow" or "deny".');
      }

      // Warn about overly permissive allow rules
      if (rule.action == 'allow' && rule.ip.endsWith('/24')) {
        _warnings.add(
            '[Firewall] Rule #$i allows access to a broad /24 subnet (${rule.ip}). '
            'Consider restricting to specific IPs.');
      }
    }

    // 6. The last rule should be a catch-all deny
    if (rules.isNotEmpty) {
      final lastRule = rules.last;
      if (lastRule.action != 'deny' || lastRule.ip != '0.0.0.0/0') {
        _warnings.add(
            '[Firewall] The last rule should be a catch-all deny (action="deny" ip="0.0.0.0/0") '
            'to block all unlisted traffic.');
      }
    }
  }
}

// ─────────────────────────────────────────────
// Reporter
// ─────────────────────────────────────────────

void printReport(ValidationResult result) {
  print('');
  print('╔══════════════════════════════════════════╗');
  print('║        XML CONFIG VALIDATION REPORT      ║');
  print('╚══════════════════════════════════════════╝');

  if (result.isValid) {
    print('✅  Status: PASSED');
  } else {
    print('❌  Status: FAILED');
  }

  print('');
  if (result.errors.isEmpty) {
    print('No errors found.');
  } else {
    print('── ERRORS (${result.errors.length}) ─────────────────────────');
    for (final e in result.errors) {
      print('  ✗ $e');
    }
  }

  print('');
  if (result.warnings.isEmpty) {
    print('No warnings.');
  } else {
    print('── WARNINGS (${result.warnings.length}) ───────────────────────');
    for (final w in result.warnings) {
      print('  ⚠ $w');
    }
  }

  print('');
  print('═' * 46);
}

// ─────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────

void main(List<String> args) {
  // Default to 'app_config.xml' or accept a path as argument
  final filePath = args.isNotEmpty ? args[0] : 'app_config.xml';

  final file = File(filePath);
  if (!file.existsSync()) {
    print('Error: File not found at "$filePath".');
    exit(1);
  }

  final xmlContent = file.readAsStringSync();

  // Parse
  final parser = AppConfigParser(xmlContent);
  final apiConfig = parser.parseApiConfig();
  final users = parser.parseUsers();
  final firewallRules = parser.parseFirewallRules();

  print('Parsed ${users.length} user(s) and ${firewallRules.length} firewall rule(s).');

  // Validate
  final validator = AppConfigValidator();
  final result = validator.validate(
    apiConfig: apiConfig,
    users: users,
    firewallRules: firewallRules,
  );

  // Report
  printReport(result);

  // Exit with error code if validation failed
  if (!result.isValid) {
    exit(1);
  }
}
