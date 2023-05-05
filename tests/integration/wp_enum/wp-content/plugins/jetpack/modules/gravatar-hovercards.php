<?php
/**
 * Module Name: Gravatar Hovercards
 * Module Description: Enable pop-up business cards over commenters’ Gravatars.
 * Sort Order: 11
 * Recommendation Order: 13
 * First Introduced: 1.1
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Social, Appearance
 * Feature: Appearance
 * Additional Search Queries: gravatar, hovercards
 *
 * @package automattic/jetpack
 */

define( 'GROFILES__CACHE_BUSTER', gmdate( 'YW' ) );

/**
 * Actions that are run on init.
 */
function grofiles_hovercards_init() {
	add_filter( 'get_avatar', 'grofiles_get_avatar', 10, 2 );
	add_action( 'wp_enqueue_scripts', 'grofiles_attach_cards' );
	add_action( 'wp_footer', 'grofiles_extra_data' );
	add_action( 'admin_init', 'grofiles_add_settings' );

	add_action( 'load-index.php', 'grofiles_admin_cards' );
	add_action( 'load-users.php', 'grofiles_admin_cards' );
	add_action( 'load-edit-comments.php', 'grofiles_admin_cards' );
	add_action( 'load-options-discussion.php', 'grofiles_admin_cards_forced' );

	add_filter( 'jetpack_module_configuration_url_gravatar-hovercards', 'gravatar_hovercards_configuration_url' );

	add_filter( 'get_comment_author_url', 'grofiles_amp_comment_author_url', 10, 2 );
}

/**
 * Set configuration page URL.
 */
function gravatar_hovercards_configuration_url() {
	return admin_url( 'options-discussion.php#show_avatars' );
}

add_action( 'jetpack_modules_loaded', 'grofiles_hovercards_init' );

/* Hovercard Settings */

/**
 * Adds Gravatar Hovercard setting
 *
 * @todo - always print HTML, hide via CSS/JS if !show_avatars
 */
function grofiles_add_settings() {
	if ( ! get_option( 'show_avatars' ) ) {
		return;
	}

	add_settings_field( 'gravatar_disable_hovercards', __( 'Gravatar Hovercards', 'jetpack' ), 'grofiles_setting_callback', 'discussion', 'avatars' );
	register_setting( 'discussion', 'gravatar_disable_hovercards', 'grofiles_hovercard_option_sanitize' );
}

/**
 * HTML for Gravatar Hovercard setting
 */
function grofiles_setting_callback() {
	global $current_user;

	$option = get_option( 'gravatar_disable_hovercards' );
	printf(
		"<label id='gravatar-hovercard-options'><input %s name='gravatar_disable_hovercards' id='gravatar_disable_hovercards' type='checkbox' value='enabled' class='code'/>%s</label>",
		checked( $option, 'enabled', false ),
		esc_html__( 'View people\'s profiles when you mouse over their Gravatars', 'jetpack' )
	);

	?>
<style type="text/css">
#grav-profile-example img {
	float: left;
}
#grav-profile-example span {
	padding: 0 1em;
}
</style>
<script type="text/javascript">
// <![CDATA[
jQuery( function($) {
	var tr = $( '#gravatar_disable_hovercards' ).change( function() {
		if ( $( this ).is( ':checked' ) ) {
			$( '#grav-profile-example' ).slideDown( 'fast' );
		} else {
			$( '#grav-profile-example' ).slideUp( 'fast' );
		}
	} ).parents( 'tr' );
	var ftr = tr.parents( 'table' ).find( 'tr:first' );
	if ( ftr.length && !ftr.find( '#gravatar_disable_hovercards' ).length ) {
		ftr.after( tr );
	}
} );
// ]]>
</script>
	<p id="grav-profile-example" class="hide-if-no-js"
		<?php
		if ( 'disabled' === $option ) {
			echo ' style="display:none"';}
		?>
		>
		<?php echo get_avatar( $current_user->ID, 64 ); ?> <span><?php esc_html_e( 'Put your mouse over your Gravatar to check out your profile.', 'jetpack' ); ?> <br class="clear" /></span></p>
	<?php
}

/**
 * Sanitation filter for Gravatar Hovercard setting
 *
 * @param string $val Disabled or enabled.
 */
function grofiles_hovercard_option_sanitize( $val ) {
	if ( 'disabled' === $val ) {
		return $val;
	}

	return $val ? 'enabled' : 'disabled';
}

/* Hovercard Display */

/**
 * Stores the gravatars' users that need extra profile data attached.
 *
 * Getter/Setter
 *
 * @param int|string|null $author Setter: User ID or email address.  Getter: null.
 *
 * @return mixed Setter: void.  Getter: array of user IDs and email addresses.
 */
function grofiles_gravatars_to_append( $author = null ) {
	static $authors = array();

	// Get.
	if ( $author === null ) {
		return array_keys( $authors );
	}

	// Set.

	if ( is_numeric( $author ) ) {
		$author = (int) $author;
	}

	$authors[ $author ] = true;
}

/**
 * In AMP, override the comment URL to allow for interactivity without
 * navigating to a new page
 *
 * @param string $url The comment author's URL.
 * @param int    $id  The comment ID.
 *
 * @return string The adjusted URL
 */
function grofiles_amp_comment_author_url( $url, $id ) {
	if ( 'comment' === get_comment_type( $id ) && class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		// @todo Disabling the comment author link in this way is not ideal since clicking the link does not cause the lightbox to open in the same way as clicking the gravatar. Likely get_comment_author_url_link should be used instead so that the href attribute can be replaced with an `on` attribute that activates the gallery.
		return '#!';
	}

	return $url;
}

/**
 * Stores the user ID or email address for each gravatar generated.
 *
 * Attached to the 'get_avatar' filter.
 *
 * @param string $avatar The <img/> element of the avatar.
 * @param mixed  $author User ID, email address, user login, comment object, user object, post object.
 *
 * @return string The <img/> element of the avatar.
 */
function grofiles_get_avatar( $avatar, $author ) {
	$is_amp = class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request();

	if ( is_numeric( $author ) ) {
		grofiles_gravatars_to_append( $author );
	} elseif ( is_string( $author ) ) {
		if ( false !== strpos( $author, '@' ) ) {
			grofiles_gravatars_to_append( $author );
		} else {
			$user = get_user_by( 'slug', $author );
			if ( $user ) {
				grofiles_gravatars_to_append( $user->ID );
			}
		}
	} elseif ( isset( $author->comment_type ) ) {
		if ( $is_amp ) {
			if ( 1 === preg_match( '/avatar\/([a-zA-Z0-9]+)\?/', $avatar, $email_hash ) ) {
				$email_hash  = $email_hash[1];
				$cache_group = 'gravatar_profiles_';
				$cache_key   = 'gravatar_profile_' . $email_hash;

				$response_body = wp_cache_get( $cache_key, $cache_group );
				if ( false === $response_body ) {
					$response = wp_remote_get( esc_url_raw( 'https://en.gravatar.com/' . $email_hash . '.json' ) );
					if ( is_array( $response ) && ! is_wp_error( $response ) ) {
						$response_body = json_decode( $response['body'] );
						wp_cache_set( $cache_key, $response_body, $cache_group, 60 * MINUTE_IN_SECONDS );
					}
				}

				$profile      = isset( $response_body->entry[0] ) ? $response_body->entry[0] : null;
				$display_name = isset( $profile->displayName ) ? $profile->displayName : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$location     = isset( $profile->currentLocation ) ? $profile->currentLocation : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
				$description  = isset( $profile->aboutMe ) ? $profile->aboutMe : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

				$avatar = '
					<figure data-amp-lightbox="true">
						' . $avatar . '
						<figcaption>
							' . esc_html( $display_name ) . ( ! empty( $location ) ? ' – ' . esc_html( $location ) : '' ) . ( ! empty( $description ) ? ' – ' . esc_html( $description ) : '' ) . '
						</figcaption>
					</figure>
				';
			}

			return $avatar;
		}

		if ( '' !== $author->comment_type && 'comment' !== $author->comment_type ) {
			return $avatar;
		}
		if ( $author->user_id ) {
			grofiles_gravatars_to_append( $author->user_id );
		} else {
			grofiles_gravatars_to_append( $author->comment_author_email );
		}
	} elseif ( isset( $author->user_login ) ) {
		grofiles_gravatars_to_append( $author->ID );
	} elseif ( isset( $author->post_author ) ) {
		grofiles_gravatars_to_append( $author->post_author );
	}

	return $avatar;
}

/**
 * Loads Gravatar Hovercard script.
 *
 * @todo is_singular() only?
 */
function grofiles_attach_cards() {

	// Is the display of Avatars disabled?
	if ( ! get_option( 'show_avatars' ) ) {
		return;
	}

	// Is the display of Gravatar Hovercards disabled?
	if ( 'disabled' === Jetpack_Options::get_option_and_ensure_autoload( 'gravatar_disable_hovercards', '0' ) ) {
		return;
	}

	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		wp_enqueue_style( 'gravatar-hovercard-style', plugins_url( '/gravatar/gravatar-hovercards-amp.css', __FILE__ ), array(), JETPACK__VERSION );
	} else {
		wp_enqueue_script( 'grofiles-cards', 'https://secure.gravatar.com/js/gprofiles.js', array(), GROFILES__CACHE_BUSTER, true );
		wp_enqueue_script( 'wpgroho', plugins_url( 'wpgroho.js', __FILE__ ), array( 'grofiles-cards' ), JETPACK__VERSION, true );
		if ( is_user_logged_in() ) {
			$cu      = wp_get_current_user();
			$my_hash = md5( $cu->user_email );
		} elseif ( ! empty( $_COOKIE[ 'comment_author_email_' . COOKIEHASH ] ) ) {
			$my_hash = md5( filter_var( wp_unslash( $_COOKIE[ 'comment_author_email_' . COOKIEHASH ] ) ) );
		} else {
			$my_hash = '';
		}
		wp_localize_script( 'wpgroho', 'WPGroHo', compact( 'my_hash' ) );
	}
}
/**
 * Add hovercards on Discussion settings panel.
 */
function grofiles_attach_cards_forced() {
	add_filter( 'pre_option_gravatar_disable_hovercards', 'grofiles_force_gravatar_enable_hovercards' );
	grofiles_attach_cards();
}
/**
 * Set hovercards as enabled on Discussion settings panel.
 */
function grofiles_force_gravatar_enable_hovercards() {
	return 'enabled';
}
/**
 * Add script to admin footer on Discussion settings panel.
 */
function grofiles_admin_cards_forced() {
	add_action( 'admin_footer', 'grofiles_attach_cards_forced' );
}
/**
 * Add script to admin footer.
 */
function grofiles_admin_cards() {
	add_action( 'admin_footer', 'grofiles_attach_cards' );
}
/**
 * Dequeue the FE assets when there are no gravatars on the page to be displayed.
 */
function grofiles_extra_data() {
	$authors = grofiles_gravatars_to_append();

	if ( ! $authors ) {
		wp_dequeue_script( 'grofiles-cards' );
		wp_dequeue_script( 'wpgroho' );
	} else {
		?>
	<div style="display:none">
		<?php
		foreach ( $authors as $author ) {
			grofiles_hovercards_data_html( $author );
		}
		?>
	</div>
		<?php
	}
}

/**
 * Echoes the data from grofiles_hovercards_data() as HTML elements.
 *
 * @since 5.5.0 Add support for a passed WP_User object
 *
 * @param int|string|WP_User $author User ID, email address, or a WP_User object.
 */
function grofiles_hovercards_data_html( $author ) {
	$data = grofiles_hovercards_data( $author );
	$hash = '';
	if ( is_numeric( $author ) ) {
		$user = get_userdata( $author );
		if ( $user ) {
			$hash = md5( $user->user_email );
		}
	} elseif ( is_email( $author ) ) {
		$hash = md5( $author );
	} elseif ( is_a( $author, 'WP_User' ) ) {
		$hash = md5( $author->user_email );
	}

	if ( ! $hash ) {
		return;
	}
	?>
	<div class="grofile-hash-map-<?php echo esc_attr( $hash ); ?>">
	<?php	foreach ( $data as $key => $value ) : ?>
		<span class="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $value ); ?></span>
<?php	endforeach; ?>
	</div>
	<?php
}

/* API */

/**
 * Returns the PHP callbacks for data sources.
 *
 * 'grofiles_hovercards_data_callbacks' filter
 *
 * @return array( data_key => data_callback, ... )
 */
function grofiles_hovercards_data_callbacks() {
	/**
	 * Filter the Gravatar Hovercard PHP callbacks.
	 *
	 * @module gravatar-hovercards
	 *
	 * @since 1.1.0
	 *
	 * @param array $args Array of data callbacks.
	 */
	return apply_filters( 'grofiles_hovercards_data_callbacks', array() );
}

/**
 * Keyed JSON object containing all profile data provided by registered callbacks
 *
 * @param int|strung $author User ID or email address.
 *
 * @return array( data_key => data, ... )
 */
function grofiles_hovercards_data( $author ) {
	$r = array();
	foreach ( grofiles_hovercards_data_callbacks() as $key => $callback ) {
		if ( ! is_callable( $callback ) ) {
			continue;
		}
		$data = call_user_func( $callback, $author, $key );
		if ( $data !== null ) {
			$r[ $key ] = $data;
		}
	}

	return $r;
}
