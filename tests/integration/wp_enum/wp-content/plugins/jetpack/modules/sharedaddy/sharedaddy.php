<?php
/**
 * Jetpack's Sharing feature, nee Sharedaddy.
 * The most super duper sharing tool on the interwebs.
 *
 * @package automattic/jetpack
 */

// Set up Sharing in wp-admin.
require_once plugin_dir_path( __FILE__ ) . 'sharing.php';

/**
 * Send an email via the Email sharing button.
 *
 * @param array $data Array of information about the shared message.
 *
 * @return void
 *
 * @deprecated 11.0
 */
function sharing_email_send_post( $data ) {

	$content = sharing_email_send_post_content( $data );
	// Borrowed from wp_mail();

	if ( empty( $_SERVER['SERVER_NAME'] ) ) {
		return;
	}

	$sitename = strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) );
	if ( substr( $sitename, 0, 4 ) === 'www.' ) {
		$sitename = substr( $sitename, 4 );
	}

	/** This filter is documented in core/src/wp-includes/pluggable.php */
	$from_email = apply_filters( 'wp_mail_from', 'wordpress@' . $sitename );

	if ( ! empty( $data['name'] ) ) {
		$s_name                    = (string) $data['name'];
		$name_needs_encoding_regex =
			'/[' .
				// SpamAssasin's list of characters which "need MIME" encoding
				'\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff' .
				// Our list of "unsafe" characters
				'<\r\n' .
			']/';

		$needs_encoding =
			// If it contains any blocked chars.
			preg_match( $name_needs_encoding_regex, $s_name ) ||
			// Or if we can't use `mb_convert_encoding`
			! function_exists( 'mb_convert_encoding' ) ||
			// Or if it's not already ASCII
			mb_convert_encoding( $data['name'], 'ASCII' ) !== $s_name;

		if ( $needs_encoding ) {
			$data['name'] = sprintf( '=?UTF-8?B?%s?=', base64_encode( $data['name'] ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		}
	}

	$headers   = array();
	$headers[] = sprintf( 'From: %1$s <%2$s>', $data['name'], $from_email );
	$headers[] = sprintf( 'Reply-To: %1$s <%2$s>', $data['name'], $data['source'] );

	// Make sure to pass the title through the normal sharing filters.
	$title = $data['sharing_source']->get_share_title( $data['post']->ID );

	/**
	 * Filter the Sharing Email Send Post Subject.
	 *
	 * @module sharedaddy
	 *
	 * @since 5.8.0
	 *
	 * @param string $var Sharing Email Send Post Subject. Default is "Shared Post".
	 */
	$subject = apply_filters( 'wp_sharing_email_send_post_subject', '[' . __( 'Shared Post', 'jetpack' ) . '] ' . $title );

	wp_mail( $data['target'], $subject, $content, $headers );
}

/**
 * Checks for spam using Akismet if available.
 * Return $data as it if email about to be send out is not spam.
 *
 * @param array $data Array of information about the shared message.
 *
 * @return array $data
 *
 * @deprecated 11.0
 */
function sharing_email_check_for_spam_via_akismet( $data ) {

	if ( ! Jetpack::is_akismet_active() ) {
		return $data;
	}

	// Prepare the body_request for akismet
	$body_request = array(
		'blog'                 => get_option( 'home' ),
		'permalink'            => $data['sharing_source']->get_share_url( $data['post']->ID ),
		'comment_type'         => 'share',
		'comment_author'       => $data['name'],
		'comment_author_email' => $data['source'],
		'comment_content'      => sharing_email_send_post_content( $data ),
		'user_agent'           => ( isset( $_SERVER['HTTP_USER_AGENT'] )
			? filter_var( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
			: null
		),
	);

	if ( method_exists( 'Akismet', 'http_post' ) ) {
		$body_request['user_ip'] = Akismet::get_ip_address();
		$response                = Akismet::http_post( build_query( $body_request ), 'comment-check' );
	} else {
		global $akismet_api_host, $akismet_api_port;
		$body_request['user_ip'] = ( isset( $_SERVER['REMOTE_ADDR'] )
			? filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: null
		);
		$response                = akismet_http_post( build_query( $body_request ), $akismet_api_host, '/1.1/comment-check', $akismet_api_port );
	}

	/*
	 * The Response is spam lets not send the email.
	 * 'true' is spam
	 */
	if (
		! empty( $response )
		&& isset( $response[1] )
		&& 'true' == trim( $response[1] ) // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual -- response comes from the Akismet API.
	) {
		return false; // don't send the email
	}
	return $data;
}

/**
 * Content of the emails sent to the target email address.
 *
 * @param array $data Array of information about the shared message.
 *
 * @return string $content
 *
 * @deprecated 11.0
 */
function sharing_email_send_post_content( $data ) {
	$content = sprintf(
		/* translators: included in email when post is shared via email. First item is sender's name. Second is sender's email address. */
		__( '%1$s (%2$s) thinks you may be interested in the following post:', 'jetpack' ),
		$data['name'],
		$data['source']
	);
	$content .= "\n\n";
	// Make sure to pass the title and URL through the normal sharing filters.
	$content .= $data['sharing_source']->get_share_title( $data['post']->ID ) . "\n";
	$content .= $data['sharing_source']->get_share_url( $data['post']->ID ) . "\n";
	return $content;
}

/**
 * Add a meta box to the post editing screen for sharing.
 *
 * @return void
 */
function sharing_add_meta_box() {
	global $post;
	if ( empty( $post ) ) { // If a current post is not defined, such as when editing a comment.
		return;
	}

	/**
	 * Filter whether to display the Sharing Meta Box or not.
	 *
	 * @module sharedaddy
	 *
	 * @since 3.8.0
	 *
	 * @param bool true Display Sharing Meta Box.
	 * @param $post Post.
	 */
	if ( ! apply_filters( 'sharing_meta_box_show', true, $post ) ) {
		return;
	}

	$post_types = get_post_types( array( 'public' => true ) );
	/**
	 * Filter the Sharing Meta Box title.
	 *
	 * @module sharedaddy
	 *
	 * @since 2.2.0
	 *
	 * @param string $var Sharing Meta Box title. Default is "Sharing".
	 */
	$title = apply_filters( 'sharing_meta_box_title', __( 'Sharing', 'jetpack' ) );
	if ( $post->ID !== get_option( 'page_for_posts' ) ) {
		foreach ( $post_types as $post_type ) {
			add_meta_box( 'sharing_meta', $title, 'sharing_meta_box_content', $post_type, 'side', 'default', array( '__back_compat_meta_box' => true ) );
		}
	}
}

/**
 * Content of the meta box.
 *
 * @param WP_Post $post The post to share.
 *
 * @return void
 */
function sharing_meta_box_content( $post ) {
	/**
	 * Fires before the sharing meta box content.
	 *
	 * @module sharedaddy
	 *
	 * @since 2.2.0
	 *
	 * @param WP_Post $post The post to share.
	 */
	do_action( 'start_sharing_meta_box_content', $post );

	$disabled = get_post_meta( $post->ID, 'sharing_disabled', true ); ?>

	<p>
		<label for="enable_post_sharing">
			<input type="checkbox" name="enable_post_sharing" id="enable_post_sharing" value="1" <?php checked( ! $disabled ); ?>>
			<?php esc_html_e( 'Show sharing buttons.', 'jetpack' ); ?>
		</label>
		<input type="hidden" name="sharing_status_hidden" value="1" />
	</p>

	<?php
	/**
	 * Fires after the sharing meta box content.
	 *
	 * @module sharedaddy
	 *
	 * @since 2.2.0
	 *
	 * @param WP_Post $post The post to share.
	 */
	do_action( 'end_sharing_meta_box_content', $post );
}

/**
 * Save new sharing status in post meta in the meta box.
 *
 * @param int $post_id Post ID.
 *
 * @return int
 */
function sharing_meta_box_save( $post_id ) {
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return $post_id;
	}

	if ( ! isset( $_POST['post_type'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core takes care of the validation.
		return $post_id;
	}

	$post_type_object = get_post_type_object( sanitize_key( $_POST['post_type'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core takes care of the validation.

	// Record sharing disable.
	if (
		$post_type_object->public
		&& current_user_can( 'edit_post', $post_id )
		&& isset( $_POST['sharing_status_hidden'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core takes care of the validation.
	) {
		if ( ! isset( $_POST['enable_post_sharing'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Core takes care of the validation.
			update_post_meta( $post_id, 'sharing_disabled', 1 );
		} else {
			delete_post_meta( $post_id, 'sharing_disabled' );
		}
	}

	return $post_id;
}

/**
 * If Sharing is disabled, disable the meta box.
 *
 * @param bool   $protected Whether the key is considered protected.
 * @param string $meta_key  Metadata key.
 *
 * @return bool
 */
function sharing_meta_box_protected( $protected, $meta_key ) {
	if ( 'sharing_disabled' === $meta_key ) {
		$protected = true;
	}

	return $protected;
}
add_filter( 'is_protected_meta', 'sharing_meta_box_protected', 10, 2 );

/**
 * Add link to sharing settings in the Plugins screen.
 *
 * @param array $links An array of plugin action links.
 *
 * @return array
 */
function sharing_plugin_settings( $links ) {
	$settings_link = '<a href="options-general.php?page=sharing.php">' . __( 'Settings', 'jetpack' ) . '</a>';
	array_unshift( $links, $settings_link );
	return $links;
}

/**
 * Add links to settings and support in the plugin row.
 *
 * @param array  $links An array of the plugin's metadata, including the version, author, author URI, and plugin URI.
 * @param string $file  Path to the plugin file relative to the plugins directory.
 *
 * @return array
 */
function sharing_add_plugin_settings( $links, $file ) {
	if ( $file === basename( __DIR__ ) . '/' . basename( __FILE__ ) ) {
		$links[] = '<a href="options-general.php?page=sharing.php">' . __( 'Settings', 'jetpack' ) . '</a>';
		$links[] = '<a href="https://support.wordpress.com/sharing/" rel="noopener noreferrer" target="_blank">' . __( 'Support', 'jetpack' ) . '</a>';
	}

	return $links;
}

/**
 * Disable sharing on the frontend if disabled in the admin.
 *
 * @return void
 */
function sharing_init() {
	if ( Jetpack_Options::get_option_and_ensure_autoload( 'sharedaddy_disable_resources', '0' ) ) {
		add_filter( 'sharing_js', '__return_false' );
		remove_action( 'wp_head', 'sharing_add_header', 1 );
	}
}

/**
 * Add settings to disable CSS and JS normally enqueued by our feature.
 *
 * @return void
 */
function sharing_global_resources() {
	$disable = get_option( 'sharedaddy_disable_resources' );
	?>
<tr valign="top">
	<th scope="row"><label for="disable_css"><?php esc_html_e( 'Disable CSS and JS', 'jetpack' ); ?></label></th>
	<td>
		<?php
		printf(
			'<input id="disable_css" type="checkbox" name="disable_resources"%1$s />  <small><em>%2$s</em></small>',
			( 1 == $disable ) ? ' checked="checked"' : '', // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
			esc_html__( 'Advanced. If this option is checked, you must include these files in your theme manually for the sharing links to work.', 'jetpack' )
		);
		?>
	</td>
</tr>
	<?php
}

/**
 * Save settings to disable CSS and JS normally enqueued by our feature.
 *
 * @return void
 */
function sharing_global_resources_save() {
	update_option( 'sharedaddy_disable_resources', isset( $_POST['disable_resources'] ) ? 1 : 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce handling is handled for all elements at once.
}

/**
 * Returns the Recaptcha site/public key.
 *
 * Supports legacy RECAPTCHA_PUBLIC_KEY or RECAPTCHA_SITE_KEY.
 *
 * @return string
 *
 * @deprecated 11.0
 */
function sharing_recaptcha_site_key() {
	if ( ! defined( 'RECAPTCHA_PUBLIC_KEY' ) && ! defined( 'RECAPTCHA_SITE_KEY' ) ) {
		return '';
	}

	if ( defined( 'RECAPTCHA_PUBLIC_KEY' ) && ! defined( 'RECAPTCHA_SITE_KEY' ) ) {
		define( 'RECAPTCHA_SITE_KEY', RECAPTCHA_PUBLIC_KEY );
	}

	return RECAPTCHA_SITE_KEY;
}

/**
 * Returns the Recaptcha private/secret key.
 *
 * Supports legacy RECAPTCHA_PRIVATE_KEY or RECAPTCHA_SECRET_KEY.
 *
 * @return string
 *
 * @deprecated 11.0
 */
function sharing_recaptcha_secret_key() {
	if ( ! defined( 'RECAPTCHA_PRIVATE_KEY' ) && ! defined( 'RECAPTCHA_SECRET_KEY' ) ) {
		return '';
	}

	if ( defined( 'RECAPTCHA_PRIVATE_KEY' ) && ! defined( 'RECAPTCHA_SECRET_KEY' ) ) {
		define( 'RECAPTCHA_SECRET_KEY', RECAPTCHA_PRIVATE_KEY );
	}

	return RECAPTCHA_SECRET_KEY;
}

/**
 * Contents of a reCAPTCHA box.
 *
 * @return void
 *
 * @deprecated 11.0
 */
function sharing_email_dialog() {
	require_once plugin_dir_path( __FILE__ ) . 'recaptcha.php';

	$recaptcha = new Jetpack_ReCaptcha(
		sharing_recaptcha_site_key(),
		sharing_recaptcha_secret_key(),
		array( 'script_lazy' => true )
	);
	echo $recaptcha->get_recaptcha_html(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in method.
}

/**
 * Short-circuit the email sharing button based on the results of reCAPTCHA.
 *
 * @param bool   $true Should we check if the message isn't spam.
 * @param object $post Post information.
 * @param array  $data Information about the shared message.
 *
 * @deprecated 11.0
 */
function sharing_email_check( $true, $post, $data ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
	require_once plugin_dir_path( __FILE__ ) . 'recaptcha.php';

	$recaptcha   = new Jetpack_ReCaptcha( sharing_recaptcha_site_key(), sharing_recaptcha_secret_key(), array( 'script_lazy' => true ) );
	$response    = ! empty( $_POST['g-recaptcha-response'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- we do not change anything on the site based on that.
		? filter_var( wp_unslash( $_POST['g-recaptcha-response'] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- we do not change anything on the site based on that.
		: '';
	$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] )
		? filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
		: '';
	$result      = $recaptcha->verify( $response, $remote_addr );

	return ( true === $result );
}

add_action( 'init', 'sharing_init' );
add_action( 'add_meta_boxes', 'sharing_add_meta_box' );
add_action( 'save_post', 'sharing_meta_box_save' );
add_action( 'edit_attachment', 'sharing_meta_box_save' );
add_action( 'sharing_global_options', 'sharing_global_resources', 30 );
add_action( 'sharing_admin_update', 'sharing_global_resources_save' );
add_action( 'plugin_action_links_' . basename( __DIR__ ) . '/' . basename( __FILE__ ), 'sharing_plugin_settings', 10, 4 );
add_filter( 'plugin_row_meta', 'sharing_add_plugin_settings', 10, 2 );
