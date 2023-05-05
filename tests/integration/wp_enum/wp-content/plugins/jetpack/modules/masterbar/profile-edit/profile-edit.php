<?php
/**
 * WP-Admin Profile edit.
 *
 * @package Jetpack
 */

use Automattic\Jetpack\Connection\Manager as Connection_Manager;

/**
 * Hides profile fields for WordPress.com connected users.
 *
 * @param WP_User $user The current WP_User object.
 */
function jetpack_masterbar_hide_profile_fields( $user ) {
	$connection_manager = new Connection_Manager( 'jetpack' );
	if ( ! $connection_manager->is_user_connected( $user->ID ) ) {
		// If this is a local user, show the default UX.
		return;
	}
	$wp_kses_rule = array(
		'a' => array(
			'href'   => array(),
			'rel'    => array(),
			'target' => array(),
		),
	);
	// Since there is no hook for altering profile fields, we will use CSS and JS.
	$name_info_wpcom_link_message = sprintf(
		/* translators: 1 link */
		__( 'WordPress.com users can change their profile’s basic details ( i.e., First Name, Last Name, Display Name, About ) in <a href="%1$s" target="_blank" rel="noopener noreferrer">WordPress.com Profile settings.</a>', 'jetpack' ),
		'https://wordpress.com/me'
	);
	$contact_info_wpcom_link_message = sprintf(
		/* translators: 1 link */
		__( 'WordPress.com users can change their profile’s email & website address in <a href="%1$s" target="_blank" rel="noopener noreferrer">WordPress.com Account settings.</a>', 'jetpack' ),
		'https://wordpress.com/me/account'
	);
	?>
	<script>
		document.addEventListener( 'DOMContentLoaded', function() {
			// Field to be hidden.
			var fieldsToHide = '.user-first-name-wrap, .user-last-name-wrap, .user-nickname-wrap, .user-display-name-wrap, .user-email-wrap, .user-url-wrap, .user-description-wrap';
			document.querySelectorAll( fieldsToHide ).forEach( element => element.classList.add( 'hidden' ) );

			// Name Info.
			var nameInfo                    = document.querySelector( '.user-first-name-wrap' ).closest( 'table' );
			var nameInfoWpcomLink           = document.createElement( 'div' );
				nameInfoWpcomLink.className = 'notice inline notice-large notice-warning';
				nameInfoWpcomLink.innerHTML = '<?php echo wp_kses( $name_info_wpcom_link_message, $wp_kses_rule ); ?>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			nameInfo.parentNode.insertBefore( nameInfoWpcomLink, nameInfo.nextSibling );

			// Contact Info.
			var contactInfo                    = document.querySelector( '.user-email-wrap' ).closest( 'table' );
			var contactInfoWpcomLink           = document.createElement( 'div' );
				contactInfoWpcomLink.className = 'notice inline notice-large notice-warning';
				contactInfoWpcomLink.innerHTML = '<?php echo wp_kses( $contact_info_wpcom_link_message, $wp_kses_rule ); ?>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			contactInfo.parentNode.insertBefore( contactInfoWpcomLink, contactInfo.nextSibling );
		});

	</script>
	<?php
}

add_action( 'personal_options', 'jetpack_masterbar_hide_profile_fields' );
