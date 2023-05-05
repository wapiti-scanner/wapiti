<?php
/**
 * Bootstrap the WP.com User profile edit restriction.
 *
 * @package automattic\jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

use Automattic\Jetpack\Connection\Manager as Connection_Manager;

require_once __DIR__ . '/profile-edit.php';
require_once __DIR__ . '/class-wpcom-user-profile-fields-revert.php';

/**
 * Prevent WP.com user profile fields (first_name, last_name, display_name, description) to be updated.
 */
function load_the_user_profile_info_revert() {
	new WPCOM_User_Profile_Fields_Revert( new Connection_Manager( 'jetpack' ) );
}

\add_action( 'load-profile.php', __NAMESPACE__ . '\load_the_user_profile_info_revert' );
\add_action( 'load-user-edit.php', __NAMESPACE__ . '\load_the_user_profile_info_revert' );
