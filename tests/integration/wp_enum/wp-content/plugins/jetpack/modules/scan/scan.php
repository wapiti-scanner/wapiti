<?php
/**
 * Jetpack Scan features that show up on the jetpack admin side.
 * - Adds a admin bar notice when the site has threats.
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Scan;

require_once __DIR__ . '/class-admin-bar-notice.php';
require_once __DIR__ . '/class-admin-sidebar-link.php';

Admin_Bar_Notice::instance();
Admin_Sidebar_Link::instance();
