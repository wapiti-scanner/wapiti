<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName)
/**
 * Module Name: Subscriptions
 * Module Description: Let visitors subscribe to new posts and comments via email
 * Sort Order: 9
 * Recommendation Order: 8
 * First Introduced: 1.2
 * Requires Connection: Yes
 * Requires User Connection: Yes
 * Auto Activate: No
 * Module Tags: Social
 * Feature: Engagement
 * Additional Search Queries: subscriptions, subscription, email, follow, followers, subscribers, signup
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Connection\XMLRPC_Async_Call;

add_action( 'jetpack_modules_loaded', 'jetpack_subscriptions_load' );

/**
 * Loads the Subscriptions module.
 */
function jetpack_subscriptions_load() {
	Jetpack::enable_module_configurable( __FILE__ );
}

/**
 * Cherry picks keys from `$_SERVER` array.
 *
 * @since 6.0.0
 *
 * @return array An array of server data.
 */
function jetpack_subscriptions_cherry_pick_server_data() {
	$data = array();

	foreach ( $_SERVER as $key => $value ) {
		if ( ! is_string( $value ) || 0 === strpos( $key, 'HTTP_COOKIE' ) ) {
			continue;
		}

		if ( 0 === strpos( $key, 'HTTP_' ) || in_array( $key, array( 'REMOTE_ADDR', 'REQUEST_URI', 'DOCUMENT_URI' ), true ) ) {
			$data[ $key ] = $value;
		}
	}

	return $data;
}

/**
 * Main class file for the Subscriptions module.
 */
class Jetpack_Subscriptions {
	/**
	 * Whether Jetpack has been instantiated or not.
	 *
	 * @var bool
	 */
	public $jetpack = false;

	/**
	 * Hash of the siteurl option.
	 *
	 * @var string
	 */
	public static $hash;

	/**
	 * Singleton
	 *
	 * @static
	 */
	public static function init() {
		static $instance = false;

		if ( ! $instance ) {
			$instance = new Jetpack_Subscriptions();
		}

		return $instance;
	}

	/**
	 * Jetpack_Subscriptions constructor.
	 */
	public function __construct() {
		$this->jetpack = Jetpack::init();

		// Don't use COOKIEHASH as it could be shared across installs && is non-unique in multisite.
		// @see: https://twitter.com/nacin/status/378246957451333632 .
		self::$hash = md5( get_option( 'siteurl' ) );

		add_filter( 'jetpack_xmlrpc_methods', array( $this, 'xmlrpc_methods' ) );

		// @todo remove sync from subscriptions and move elsewhere...

		// Add Configuration Page.
		add_action( 'admin_init', array( $this, 'configure' ) );

		// Catch subscription widget submits.
		if ( isset( $_REQUEST['jetpack_subscriptions_widget'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce checked in widget_submit() for logged in users.
			add_action( 'template_redirect', array( $this, 'widget_submit' ) );
		}

		// Set up the comment subscription checkboxes.
		add_filter( 'comment_form_submit_field', array( $this, 'comment_subscribe_init' ), 10, 2 );

		// Catch comment posts and check for subscriptions.
		add_action( 'comment_post', array( $this, 'comment_subscribe_submit' ), 50, 2 );

		// Adds post meta checkbox in the post submit metabox.
		add_action( 'post_submitbox_misc_actions', array( $this, 'subscription_post_page_metabox' ) );

		add_action( 'transition_post_status', array( $this, 'maybe_send_subscription_email' ), 10, 3 );

		add_filter( 'jetpack_published_post_flags', array( $this, 'set_post_flags' ), 10, 2 );

		add_filter( 'post_updated_messages', array( $this, 'update_published_message' ), 18, 1 );

		// Set "social_notifications_subscribe" option during the first-time activation.
		add_action( 'jetpack_activate_module_subscriptions', array( $this, 'set_social_notifications_subscribe' ) );

		// Hide subscription messaging in Publish panel for posts that were published in the past
		add_action( 'init', array( $this, 'register_post_meta' ), 20 );
		add_action( 'transition_post_status', array( $this, 'maybe_set_first_published_status' ), 10, 3 );
	}

	/**
	 * Jetpack_Subscriptions::xmlrpc_methods()
	 *
	 * Register subscriptions methods with the Jetpack XML-RPC server.
	 *
	 * @param array $methods Methods being registered.
	 */
	public function xmlrpc_methods( $methods ) {
		return array_merge(
			$methods,
			array(
				'jetpack.subscriptions.subscribe' => array( $this, 'subscribe' ),
			)
		);
	}

	/**
	 * Disable Subscribe on Single Post
	 * Register post meta
	 */
	public function subscription_post_page_metabox() {
		if (
			/**
			 * Filter whether or not to show the per-post subscription option.
			 *
			 * @module subscriptions
			 *
			 * @since 3.7.0
			 *
			 * @param bool true = show checkbox option on all new posts | false = hide the option.
			 */
			! apply_filters( 'jetpack_allow_per_post_subscriptions', false ) ) {
			return;
		}

		if ( has_filter( 'jetpack_subscriptions_exclude_these_categories' ) || has_filter( 'jetpack_subscriptions_include_only_these_categories' ) ) {
			return;
		}

		global $post;
		$disable_subscribe_value = get_post_meta( $post->ID, '_jetpack_dont_email_post_to_subs', true );
		// only show checkbox if post hasn't been published and is a 'post' post type.
		if ( get_post_status( $post->ID ) !== 'publish' && get_post_type( $post->ID ) === 'post' ) :
			// Nonce it.
			wp_nonce_field( 'disable_subscribe', 'disable_subscribe_nonce' );
			?>
			<div class="misc-pub-section">
				<label for="_jetpack_dont_email_post_to_subs"><?php esc_html_e( 'Jetpack Subscriptions:', 'jetpack' ); ?></label><br>
				<input type="checkbox" name="_jetpack_dont_email_post_to_subs" id="jetpack-per-post-subscribe" value="1" <?php checked( $disable_subscribe_value, 1, true ); ?> />
				<?php esc_html_e( 'Don&#8217;t send this to subscribers', 'jetpack' ); ?>
			</div>
			<?php
		endif;
	}

	/**
	 * Checks whether or not the post should be emailed to subscribers
	 *
	 * It checks for the following things in order:
	 * - Usage of filter jetpack_subscriptions_exclude_these_categories
	 * - Usage of filter jetpack_subscriptions_include_only_these_categories
	 * - Existence of the per-post checkbox option
	 *
	 * Only one of these can be used at any given time.
	 *
	 * @param string $new_status Tthe "new" post status of the transition when saved.
	 * @param string $old_status The "old" post status of the transition when saved.
	 * @param object $post obj The post object.
	 */
	public function maybe_send_subscription_email( $new_status, $old_status, $post ) {

		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return;
		}

		// Make sure that the checkbox is preseved.
		if ( ! empty( $_POST['disable_subscribe_nonce'] ) && wp_verify_nonce( $_POST['disable_subscribe_nonce'], 'disable_subscribe' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WP Core doesn't unslash or sanitize nonces either.
			$set_checkbox = isset( $_POST['_jetpack_dont_email_post_to_subs'] ) ? 1 : 0;
			update_post_meta( $post->ID, '_jetpack_dont_email_post_to_subs', $set_checkbox );
		}
	}

	/**
	 * Message used when publishing a post.
	 *
	 * @param array $messages Message array for a post.
	 */
	public function update_published_message( $messages ) {
		global $post;
		if ( ! $this->should_email_post_to_subscribers( $post ) ) {
			return $messages;
		}

		$view_post_link_html = sprintf(
			' <a href="%1$s">%2$s</a>',
			esc_url( get_permalink( $post ) ),
			__( 'View post', 'jetpack' )
		);

		$messages['post'][6] = sprintf(
			/* translators: Message shown after a post is published */
			esc_html__( 'Post published and sending emails to subscribers.', 'jetpack' )
		) . $view_post_link_html;
		return $messages;
	}

	/**
	 * Determine if a post should notifiy subscribers via email.
	 *
	 * @param object $post The post.
	 */
	public function should_email_post_to_subscribers( $post ) {
		$should_email = true;
		if ( get_post_meta( $post->ID, '_jetpack_dont_email_post_to_subs', true ) ) {
			return false;
		}

		// Only posts are currently supported.
		if ( 'post' !== $post->post_type ) {
			return false;
		}

		// Private posts are not sent to subscribers.
		if ( 'private' === $post->post_status ) {
			return false;
		}

		/**
		 * Array of categories that will never trigger subscription emails.
		 *
		 * Will not send subscription emails from any post from within these categories.
		 *
		 * @module subscriptions
		 *
		 * @since 3.7.0
		 *
		 * @param array $args Array of category slugs or ID's.
		 */
		$excluded_categories = apply_filters( 'jetpack_subscriptions_exclude_these_categories', array() );

		// Never email posts from these categories.
		if ( ! empty( $excluded_categories ) && in_category( $excluded_categories, $post->ID ) ) {
			$should_email = false;
		}

		/**
		 * ONLY send subscription emails for these categories
		 *
		 * Will ONLY send subscription emails to these categories.
		 *
		 * @module subscriptions
		 *
		 * @since 3.7.0
		 *
		 * @param array $args Array of category slugs or ID's.
		 */
		$only_these_categories = apply_filters( 'jetpack_subscriptions_exclude_all_categories_except', array() );

		// Only emails posts from these categories.
		if ( ! empty( $only_these_categories ) && ! in_category( $only_these_categories, $post->ID ) ) {
			$should_email = false;
		}

		return $should_email;
	}

	/**
	 * Retrieve which flags should be added to a particular post.
	 *
	 * @param array  $flags Flags to be added.
	 * @param object $post A post object.
	 */
	public function set_post_flags( $flags, $post ) {
		$flags['send_subscription'] = $this->should_email_post_to_subscribers( $post );
		return $flags;
	}

	/**
	 * Jetpack_Subscriptions::configure()
	 *
	 * Jetpack Subscriptions configuration screen.
	 */
	public function configure() {
		// Create the section.
		add_settings_section(
			'jetpack_subscriptions',
			__( 'Jetpack Subscriptions Settings', 'jetpack' ),
			array( $this, 'subscriptions_settings_section' ),
			'discussion'
		);

		/** Subscribe to Posts */

		add_settings_field(
			'jetpack_subscriptions_post_subscribe',
			__( 'Follow Blog', 'jetpack' ),
			array( $this, 'subscription_post_subscribe_setting' ),
			'discussion',
			'jetpack_subscriptions'
		);

		register_setting(
			'discussion',
			'stb_enabled'
		);

		/** Subscribe to Comments */

		add_settings_field(
			'jetpack_subscriptions_comment_subscribe',
			__( 'Follow Comments', 'jetpack' ),
			array( $this, 'subscription_comment_subscribe_setting' ),
			'discussion',
			'jetpack_subscriptions'
		);

		register_setting(
			'discussion',
			'stc_enabled'
		);

		/** Email me whenever: Someone follows my blog */
		/* @since 8.1 */

		add_settings_section(
			'notifications_section',
			__( 'Someone follows my blog', 'jetpack' ),
			array( $this, 'social_notifications_subscribe_section' ),
			'discussion'
		);

		add_settings_field(
			'jetpack_subscriptions_social_notifications_subscribe',
			__( 'Email me whenever', 'jetpack' ),
			array( $this, 'social_notifications_subscribe_field' ),
			'discussion',
			'notifications_section'
		);

		register_setting(
			'discussion',
			'social_notifications_subscribe',
			array( $this, 'social_notifications_subscribe_validate' )
		);

		/** Subscription Messaging Options */

		register_setting(
			'reading',
			'subscription_options',
			array( $this, 'validate_settings' )
		);

		add_settings_section(
			'email_settings',
			__( 'Follower Settings', 'jetpack' ),
			array( $this, 'reading_section' ),
			'reading'
		);

		add_settings_field(
			'invitation',
			__( 'Blog follow email text', 'jetpack' ),
			array( $this, 'setting_invitation' ),
			'reading',
			'email_settings'
		);

		add_settings_field(
			'comment-follow',
			__( 'Comment follow email text', 'jetpack' ),
			array( $this, 'setting_comment_follow' ),
			'reading',
			'email_settings'
		);
	}

	/**
	 * Discussions setting section blurb.
	 */
	public function subscriptions_settings_section() {
		?>
		<p id="jetpack-subscriptions-settings"><?php esc_html_e( 'Change whether your visitors can subscribe to your posts or comments or both.', 'jetpack' ); ?></p>

		<?php
	}

	/**
	 * Post Subscriptions Toggle.
	 */
	public function subscription_post_subscribe_setting() {

		$stb_enabled = get_option( 'stb_enabled', 1 );
		?>

		<p class="description">
			<input type="checkbox" name="stb_enabled" id="jetpack-post-subscribe" value="1" <?php checked( $stb_enabled, 1 ); ?> />
			<?php
			echo wp_kses(
				__(
					"Show a <em>'follow blog'</em> option in the comment form",
					'jetpack'
				),
				array( 'em' => array() )
			);
			?>
		</p>
		<?php
	}

	/**
	 * Comments Subscriptions Toggle.
	 */
	public function subscription_comment_subscribe_setting() {

		$stc_enabled = get_option( 'stc_enabled', 1 );
		?>

		<p class="description">
			<input type="checkbox" name="stc_enabled" id="jetpack-comment-subscribe" value="1" <?php checked( $stc_enabled, 1 ); ?> />
			<?php
			echo wp_kses(
				__(
					"Show a <em>'follow comments'</em> option in the comment form",
					'jetpack'
				),
				array( 'em' => array() )
			);
			?>
		</p>

		<?php
	}

	/**
	 * Someone follows my blog section
	 *
	 * @since 8.1
	 */
	public function social_notifications_subscribe_section() {
		// Atypical usage here. We emit jquery to move subscribe notification checkbox to be with the rest of the email notification settings.
		?>
		<script type="text/javascript">
			jQuery( function( $ )  {
				var table = $( '#social_notifications_subscribe' ).parents( 'table:first' ),
					header = table.prevAll( 'h2:first' ),
					newParent = $( '#moderation_notify' ).parent( 'label' ).parent();

				if ( ! table.length || ! header.length || ! newParent.length ) {
					return;
				}

				newParent.append( '<br/>' ).append( table.end().parent( 'label' ).siblings().andSelf() );
				header.remove();
				table.remove();
			} );
		</script>
		<?php
	}

	/**
	 * Someone follows my blog Toggle
	 *
	 * @since 8.1
	 */
	public function social_notifications_subscribe_field() {
		$checked = (int) ( 'on' === get_option( 'social_notifications_subscribe', 'on' ) );
		?>

		<label>
			<input type="checkbox" name="social_notifications_subscribe" id="social_notifications_subscribe" value="1" <?php checked( $checked ); ?> />
			<?php
				/* translators: this is a label for a setting that starts with "Email me whenever" */
				esc_html_e( 'Someone follows my blog', 'jetpack' );
			?>
		</label>
		<?php
	}

	/**
	 * Validate "Someone follows my blog" option
	 *
	 * @since 8.1
	 *
	 * @param String $input the input string to be validated.
	 * @return string on|off
	 */
	public function social_notifications_subscribe_validate( $input ) {
		// If it's not set (was unchecked during form submission) or was set to off (during option update), return 'off'.
		if ( ! $input || 'off' === $input ) {
			return 'off';
		}

		// Otherwise we return 'on'.
		return 'on';
	}

	/**
	 * Validate settings for the Subscriptions module.
	 *
	 * @param array $settings Settings to be validated.
	 */
	public function validate_settings( $settings ) {
		global $allowedposttags;

		$default = $this->get_default_settings();

		// Blog Follow.
		$settings['invitation'] = trim( wp_kses( $settings['invitation'], $allowedposttags ) );
		if ( empty( $settings['invitation'] ) ) {
			$settings['invitation'] = $default['invitation'];
		}

		// Comments Follow (single post).
		$settings['comment_follow'] = trim( wp_kses( $settings['comment_follow'], $allowedposttags ) );
		if ( empty( $settings['comment_follow'] ) ) {
			$settings['comment_follow'] = $default['comment_follow'];
		}

		return $settings;
	}

	/**
	 * HTML output helper for Reading section.
	 */
	public function reading_section() {
		echo '<p id="follower-settings">';
		esc_html_e( 'These settings change emails sent from your blog to followers.', 'jetpack' );
		echo '</p>';
	}

	/**
	 * HTML output helper for Invitation section.
	 */
	public function setting_invitation() {
		$settings = $this->get_settings();
		echo '<textarea name="subscription_options[invitation]" class="large-text" cols="50" rows="5">' . esc_textarea( $settings['invitation'] ) . '</textarea>';
		echo '<p><span class="description">' . esc_html__( 'Introduction text sent when someone follows your blog. (Site and confirmation details will be automatically added for you.)', 'jetpack' ) . '</span></p>';
	}

	/**
	 * HTML output helper for Comment Follow section.
	 */
	public function setting_comment_follow() {
		$settings = $this->get_settings();
		echo '<textarea name="subscription_options[comment_follow]" class="large-text" cols="50" rows="5">' . esc_textarea( $settings['comment_follow'] ) . '</textarea>';
		echo '<p><span class="description">' . esc_html__( 'Introduction text sent when someone follows a post on your blog. (Site and confirmation details will be automatically added for you.)', 'jetpack' ) . '</span></p>';
	}

	/**
	 * Get default settings for the Subscriptions module.
	 */
	public function get_default_settings() {
		$site_url    = get_home_url();
		$display_url = preg_replace( '(^https?://)', '', untrailingslashit( $site_url ) );

		return array(
			/* translators: Both %1$s and %2$s is site address */
			'invitation'     => sprintf( __( "Howdy,\nYou recently subscribed to <a href='%1\$s'>%2\$s</a> and we need to verify the email you provided. Once you confirm below, you'll be able to receive and read new posts.\n\nIf you believe this is an error, ignore this message and nothing more will happen.", 'jetpack' ), $site_url, $display_url ),
			'comment_follow' => __( "Howdy.\n\nYou recently followed one of my posts. This means you will receive an email when new comments are posted.\n\nTo activate, click confirm below. If you believe this is an error, ignore this message and we'll never bother you again.", 'jetpack' ),
		);
	}

	/**
	 * Reeturn merged `subscription_options` option with module default settings.
	 */
	public function get_settings() {
		return wp_parse_args( (array) get_option( 'subscription_options' ), $this->get_default_settings() );
	}

	/**
	 * Jetpack_Subscriptions::subscribe()
	 *
	 * Send a synchronous XML-RPC subscribe to blog posts or subscribe to post comments request.
	 *
	 * @param string $email being subscribed.
	 * @param array  $post_ids (optional) defaults to 0 for blog posts only: array of post IDs to subscribe to blog's posts.
	 * @param bool   $async    (optional) Should the subscription be performed asynchronously?  Defaults to true.
	 * @param array  $extra_data Additional data passed to the `jetpack.subscribeToSite` call.
	 *
	 * @return true|WP_Error true on success
	 *  invalid_email   : not a valid email address
	 *  invalid_post_id : not a valid post ID
	 *  unknown_post_id : unknown post
	 *  not_subscribed  : strange error.  Jetpack servers at WordPress.com could subscribe the email.
	 *  disabled        : Site owner has disabled subscriptions.
	 *  active          : Already subscribed.
	 *  pending         : Tried to subscribe before but the confirmation link is never clicked. No confirmation email is sent.
	 *  unknown         : strange error.  Jetpack servers at WordPress.com returned something malformed.
	 *  unknown_status  : strange error.  Jetpack servers at WordPress.com returned something I didn't understand.
	 */
	public function subscribe( $email, $post_ids = 0, $async = true, $extra_data = array() ) {
		if ( ! is_email( $email ) ) {
			return new WP_Error( 'invalid_email' );
		}

		if ( ! $async ) {
			$xml = new Jetpack_IXR_ClientMulticall();
		}

		foreach ( (array) $post_ids as $post_id ) {
			$post_id = (int) $post_id;
			if ( $post_id < 0 ) {
				return new WP_Error( 'invalid_post_id' );
			} elseif ( $post_id && ! get_post( $post_id ) ) {
				return new WP_Error( 'unknown_post_id' );
			}

			if ( $async ) {
				XMLRPC_Async_Call::add_call( 'jetpack.subscribeToSite', 0, $email, $post_id, serialize( $extra_data ) ); //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
			} else {
				$xml->addCall( 'jetpack.subscribeToSite', $email, $post_id, serialize( $extra_data ) ); //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
			}
		}

		if ( $async ) {
			return;
		}

		// Call.
		$xml->query();

		if ( $xml->isError() ) {
			return $xml->get_jetpack_error();
		}

		$responses = $xml->getResponse();

		$r = array();
		foreach ( (array) $responses as $response ) {
			if ( isset( $response['faultCode'] ) || isset( $response['faultString'] ) ) {
				$r[] = $xml->get_jetpack_error( $response['faultCode'], $response['faultString'] );
				continue;
			}

			if ( ! is_array( $response[0] ) || empty( $response[0]['status'] ) ) {
				$r[] = new WP_Error( 'unknown' );
				continue;
			}

			switch ( $response[0]['status'] ) {
				case 'error':
					$r[] = new WP_Error( 'not_subscribed' );
					continue 2;
				case 'disabled':
					$r[] = new WP_Error( 'disabled' );
					continue 2;
				case 'active':
					$r[] = new WP_Error( 'active' );
					continue 2;
				case 'confirming':
					$r[] = true;
					continue 2;
				case 'pending':
					$r[] = new WP_Error( 'pending' );
					continue 2;
				default:
					$r[] = new WP_Error( 'unknown_status', (string) $response[0]['status'] );
					continue 2;
			}
		}

		return $r;
	}

	/**
	 * Jetpack_Subscriptions::widget_submit()
	 *
	 * When a user submits their email via the blog subscription widget, check the details and call the subsribe() method.
	 */
	public function widget_submit() {
		// Check the nonce.
		if ( is_user_logged_in() ) {
			check_admin_referer( 'blogsub_subscribe_' . get_current_blog_id() );
		}

		if ( empty( $_REQUEST['email'] ) || ! is_string( $_REQUEST['email'] ) ) {
			return false;
		}

		$redirect_fragment = false;
		if ( isset( $_REQUEST['redirect_fragment'] ) ) {
			$redirect_fragment = preg_replace( '/[^a-z0-9_-]/i', '', $_REQUEST['redirect_fragment'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- This is manually unslashing and sanitizing.
		}
		if ( ! $redirect_fragment || ! is_string( $redirect_fragment ) ) {
			$redirect_fragment = 'subscribe-blog';
		}

		$subscribe = self::subscribe(
			isset( $_REQUEST['email'] ) ? wp_unslash( $_REQUEST['email'] ) : null, // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Validated inside self::subscribe().
			0,
			false,
			array(
				'source'         => 'widget',
				'widget-in-use'  => is_active_widget( false, false, 'blog_subscription', true ) ? 'yes' : 'no',
				'comment_status' => '',
				'server_data'    => jetpack_subscriptions_cherry_pick_server_data(),
			)
		);

		if ( is_wp_error( $subscribe ) ) {
			$error = $subscribe->get_error_code();
		} else {
			$error = false;
			foreach ( $subscribe as $response ) {
				if ( is_wp_error( $response ) ) {
					$error = $response->get_error_code();
					break;
				}
			}
		}

		switch ( $error ) {
			case false:
				$result = 'success';
				break;
			case 'invalid_email':
				$result = $error;
				break;
			case 'blocked_email':
				$result = 'opted_out';
				break;
			case 'active':
				$result = 'already';
				break;
			case 'flooded_email':
				$result = 'many_pending_subs';
				break;
			case 'pending':
				$result = 'pending';
				break;
			default:
				$result = 'error';
				break;
		}

		$redirect = add_query_arg( 'subscribe', $result );

		/**
		 * Fires on each subscription form submission.
		 *
		 * @module subscriptions
		 *
		 * @since 3.7.0
		 *
		 * @param string $result Result of form submission: success, invalid_email, already, error.
		 */
		do_action( 'jetpack_subscriptions_form_submission', $result );

		wp_safe_redirect( "$redirect#$redirect_fragment" );
		exit;
	}

	/**
	 * Jetpack_Subscriptions::comment_subscribe_init()
	 *
	 * Set up and add the comment subscription checkbox to the comment form.
	 *
	 * @param string $submit_button HTML markup for the submit field.
	 */
	public function comment_subscribe_init( $submit_button ) {
		global $post;

		$comments_checked = '';
		$blog_checked     = '';

		// Check for a comment / blog submission and set a cookie to retain the setting and check the boxes.
		if ( isset( $_COOKIE[ 'jetpack_comments_subscribe_' . self::$hash . '_' . $post->ID ] ) ) {
			$comments_checked = ' checked="checked"';
		}

		if ( isset( $_COOKIE[ 'jetpack_blog_subscribe_' . self::$hash ] ) ) {
			$blog_checked = ' checked="checked"';
		}

		// Some themes call this function, don't show the checkbox again.
		remove_action( 'comment_form', 'subscription_comment_form' );

		// Check if Mark Jaquith's Subscribe to Comments plugin is active - if so, suppress Jetpack checkbox.

		$str = '';

		if ( false === has_filter( 'comment_form', 'show_subscription_checkbox' ) && 1 === (int) get_option( 'stc_enabled', 1 ) && empty( $post->post_password ) && 'post' === get_post_type() ) {
			// Subscribe to comments checkbox.
			$str             .= '<p class="comment-subscription-form"><input type="checkbox" name="subscribe_comments" id="subscribe_comments" value="subscribe" style="width: auto; -moz-appearance: checkbox; -webkit-appearance: checkbox;"' . $comments_checked . ' /> ';
			$comment_sub_text = __( 'Notify me of follow-up comments by email.', 'jetpack' );
			$str             .= '<label class="subscribe-label" id="subscribe-label" for="subscribe_comments">' . esc_html(
				/**
				 * Filter the Subscribe to comments text appearing below the comment form.
				 *
				 * @module subscriptions
				 *
				 * @since 3.4.0
				 *
				 * @param string $comment_sub_text Subscribe to comments text.
				 */
				apply_filters( 'jetpack_subscribe_comment_label', $comment_sub_text )
			) . '</label>';
			$str .= '</p>';
		}

		if ( 1 === (int) get_option( 'stb_enabled', 1 ) ) {
			// Subscribe to blog checkbox.
			$str          .= '<p class="comment-subscription-form"><input type="checkbox" name="subscribe_blog" id="subscribe_blog" value="subscribe" style="width: auto; -moz-appearance: checkbox; -webkit-appearance: checkbox;"' . $blog_checked . ' /> ';
			$blog_sub_text = __( 'Notify me of new posts by email.', 'jetpack' );
			$str          .= '<label class="subscribe-label" id="subscribe-blog-label" for="subscribe_blog">' . esc_html(
				/**
				 * Filter the Subscribe to blog text appearing below the comment form.
				 *
				 * @module subscriptions
				 *
				 * @since 3.4.0
				 *
				 * @param string $comment_sub_text Subscribe to blog text.
				 */
				apply_filters( 'jetpack_subscribe_blog_label', $blog_sub_text )
			) . '</label>';
			$str .= '</p>';
		}

		/**
		 * Filter the output of the subscription options appearing below the comment form.
		 *
		 * @module subscriptions
		 *
		 * @since 1.2.0
		 *
		 * @param string $str Comment Subscription form HTML output.
		 */
		$str = apply_filters( 'jetpack_comment_subscription_form', $str );

		return $str . $submit_button;
	}

	/**
	 * Jetpack_Subscriptions::comment_subscribe_init()
	 *
	 * When a user checks the comment subscribe box and submits a comment, subscribe them to the comment thread.
	 *
	 * @param int|string $comment_id Comment thread being subscribed to.
	 * @param string     $approved Comment status.
	 */
	public function comment_subscribe_submit( $comment_id, $approved ) {
		if ( 'spam' === $approved ) {
			return;
		}

		$comment = get_comment( $comment_id );
		if ( ! $comment ) {
			return;
		}

		// Set cookies for this post/comment.
		$this->set_cookies( isset( $_REQUEST['subscribe_comments'] ), $comment->comment_post_ID, isset( $_REQUEST['subscribe_blog'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( ! isset( $_REQUEST['subscribe_comments'] ) && ! isset( $_REQUEST['subscribe_blog'] ) ) {  // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$post_ids = array();

		if ( isset( $_REQUEST['subscribe_comments'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$post_ids[] = $comment->comment_post_ID;
		}

		if ( isset( $_REQUEST['subscribe_blog'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$post_ids[] = 0;
		}

		$result = self::subscribe(
			$comment->comment_author_email,
			$post_ids,
			true,
			array(
				'source'         => 'comment-form',
				'widget-in-use'  => is_active_widget( false, false, 'blog_subscription', true ) ? 'yes' : 'no',
				'comment_status' => $approved,
				'server_data'    => jetpack_subscriptions_cherry_pick_server_data(),
			)
		);

		/**
		 * Fires on each comment subscription form submission.
		 *
		 * @module subscriptions
		 *
		 * @since 5.5.0
		 *
		 * @param NULL|WP_Error $result Result of form submission: NULL on success, WP_Error otherwise.
		 * @param array $post_ids An array of post IDs that the user subscribed to, 0 means blog subscription.
		 */
		do_action( 'jetpack_subscriptions_comment_form_submission', $result, $post_ids );
	}

	/**
	 * Jetpack_Subscriptions::set_cookies()
	 *
	 * Set a cookie to save state on the comment and post subscription checkboxes.
	 *
	 * @param bool $subscribe_to_post Whether the user chose to subscribe to subsequent comments on this post.
	 * @param int  $post_id If $subscribe_to_post is true, the post ID they've subscribed to.
	 * @param bool $subscribe_to_blog Whether the user chose to subscribe to all new posts on the blog.
	 */
	public function set_cookies( $subscribe_to_post = false, $post_id = null, $subscribe_to_blog = false ) {
		$post_id = (int) $post_id;

		/** This filter is already documented in core/wp-includes/comment-functions.php */
		$cookie_lifetime = apply_filters( 'comment_cookie_lifetime', 30000000 );

		/**
		 * Filter the Jetpack Comment cookie path.
		 *
		 * @module subscriptions
		 *
		 * @since 2.5.0
		 *
		 * @param string COOKIEPATH Cookie path.
		 */
		$cookie_path = apply_filters( 'jetpack_comment_cookie_path', COOKIEPATH );

		/**
		 * Filter the Jetpack Comment cookie domain.
		 *
		 * @module subscriptions
		 *
		 * @since 2.5.0
		 *
		 * @param string COOKIE_DOMAIN Cookie domain.
		 */
		$cookie_domain = apply_filters( 'jetpack_comment_cookie_domain', COOKIE_DOMAIN );

		if ( $subscribe_to_post && $post_id >= 0 ) {
			setcookie( 'jetpack_comments_subscribe_' . self::$hash . '_' . $post_id, 1, time() + $cookie_lifetime, $cookie_path, $cookie_domain, is_ssl(), true );
		} else {
			setcookie( 'jetpack_comments_subscribe_' . self::$hash . '_' . $post_id, '', time() - 3600, $cookie_path, $cookie_domain, is_ssl(), true );
		}

		if ( $subscribe_to_blog ) {
			setcookie( 'jetpack_blog_subscribe_' . self::$hash, 1, time() + $cookie_lifetime, $cookie_path, $cookie_domain, is_ssl(), true );
		} else {
			setcookie( 'jetpack_blog_subscribe_' . self::$hash, '', time() - 3600, $cookie_path, $cookie_domain, is_ssl(), true );
		}
	}

	/**
	 * Set the social_notifications_subscribe option to `off` when the Subscriptions module is activated in the first time.
	 *
	 * @since 8.1
	 *
	 * @return void
	 */
	public function set_social_notifications_subscribe() {
		if ( false === get_option( 'social_notifications_subscribe' ) ) {
			add_option( 'social_notifications_subscribe', 'off' );
		}
	}

	/**
	 * Save a flag when a post was ever published.
	 *
	 * It saves the post meta when the post was published and becomes a draft.
	 * Then this meta is used to hide subscription messaging in Publish panel.
	 *
	 * @param string $new_status Tthe "new" post status of the transition when saved.
	 * @param string $old_status The "old" post status of the transition when saved.
	 * @param object $post obj The post object.
	 */
	public function maybe_set_first_published_status( $new_status, $old_status, $post ) {
		$was_post_ever_published = get_post_meta( $post->ID, '_jetpack_post_was_ever_published', true );
		if ( ! $was_post_ever_published && 'publish' === $old_status && 'draft' === $new_status ) {
			update_post_meta( $post->ID, '_jetpack_post_was_ever_published', true );
		}
	}

	/**
	 * Checks if the current user can publish posts.
	 *
	 * @return bool
	 */
	public function first_published_status_meta_auth_callback() {
		if ( current_user_can( 'publish_posts' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * Registers the 'post_was_ever_published' post meta for use in the REST API.
	 */
	public function register_post_meta() {
		$jetpack_post_was_ever_published = array(
			'type'          => 'boolean',
			'description'   => __( 'Whether the post was ever published.', 'jetpack' ),
			'single'        => true,
			'default'       => false,
			'show_in_rest'  => array(
				'name' => 'jetpack_post_was_ever_published',
			),
			'auth_callback' => array( $this, 'first_published_status_meta_auth_callback' ),
		);

		register_meta( 'post', '_jetpack_post_was_ever_published', $jetpack_post_was_ever_published );
	}

}

Jetpack_Subscriptions::init();

require __DIR__ . '/subscriptions/views.php';
