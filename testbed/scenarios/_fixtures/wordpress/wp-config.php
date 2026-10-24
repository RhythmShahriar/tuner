<?php
// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

// A scenario fixture: not a real site and not real secrets.
define('DB_NAME', 'scenario');
define('DB_USER', 'scenario');
define('DB_PASSWORD', 'scenario-db-password');
define('DISALLOW_FILE_EDIT', true);
define('FORCE_SSL_ADMIN', true);
$table_prefix = 'sc_';
define('AUTH_KEY', 'scenario-a1'); define('SECURE_AUTH_KEY', 'scenario-a2');
define('LOGGED_IN_KEY', 'scenario-a3'); define('NONCE_KEY', 'scenario-a4');
define('AUTH_SALT', 'scenario-a5'); define('SECURE_AUTH_SALT', 'scenario-a6');
define('LOGGED_IN_SALT', 'scenario-a7'); define('NONCE_SALT', 'scenario-a8');
require_once ABSPATH . 'wp-settings.php';
