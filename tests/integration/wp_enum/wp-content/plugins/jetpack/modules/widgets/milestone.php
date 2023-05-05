<?php
/**
 * Milestone widget loader.
 *
 * Everything happens within the folder, but Jetpack loads widgets via a widgets/*.php scheme.
 *
 * @package automattic/jetpack
 */

/**
 * Includes the milestone widget.  This makes it easier to keep the /milestone/ dir content in sync with wpcom.
 */
require_once __DIR__ . '/milestone/milestone.php';
