<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
use const Automattic\Jetpack\Extensions\Subscriptions\META_NAME_FOR_POST_LEVEL_ACCESS_SETTINGS;

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Jetpack_Subscriptions_Widget main view class.
 */
class Jetpack_Subscriptions_Widget extends WP_Widget {

	const ID_BASE = 'blog_subscription';

	/**
	 * Track number of rendered Subscription widgets. The count is used for class names and widget IDs.
	 *
	 * @var int
	 */
	public static $instance_count = 0;

	/**
	 * When printing the submit button, what tags are allowed.
	 *
	 * @var array
	 */
	public static $allowed_html_tags_for_submit_button = array(
		'br'     => array(),
		's'      => array(),
		'strong' => array(),
		'em'     => array(),
	);

	/**
	 * Use this variable when printing the message after submitting an email in subscription widgets
	 *
	 * @var array what tags are allowed
	 */
	public static $allowed_html_tags_for_message = array(
		'a'  => array(
			'href'   => array(),
			'title'  => array(),
			'rel'    => array(),
			'target' => array(),
		),
		'br' => array(),
	);

	/**
	 * Jetpack_Subscriptions_Widget constructor.
	 */
	public function __construct() {
		$widget_ops = array(
			'classname'                   => 'widget_blog_subscription jetpack_subscription_widget',
			'description'                 => __( 'Add an email signup form to allow people to subscribe to your blog.', 'jetpack' ),
			'customize_selective_refresh' => true,
			'show_instance_in_rest'       => true,
		);

		$name = self::is_jetpack() ?
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Blog Subscriptions', 'jetpack' ) ) :
			__( 'Follow Blog', 'jetpack' );

		parent::__construct(
			'blog_subscription',
			$name,
			$widget_ops
		);

		if ( self::is_jetpack() &&
			(
				is_active_widget( false, false, $this->id_base ) ||
				is_active_widget( false, false, 'monster' ) ||
				is_customize_preview()
			)
		) {
			add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_style' ) );
		}

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "Blog Subscription" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = self::ID_BASE;
		return $widget_types;
	}

	/**
	 * Enqueue the form's CSS.
	 *
	 * @since 4.5.0
	 */
	public function enqueue_style() {
		wp_register_style(
			'jetpack-subscriptions',
			plugins_url( 'subscriptions.css', __FILE__ ),
			array(),
			JETPACK__VERSION
		);
		wp_enqueue_style( 'jetpack-subscriptions' );
	}

	/**
	 * Renders a full widget either within the context of WordPress widget, or in response to a shortcode.
	 *
	 * @param array $args Display arguments including 'before_title', 'after_title', 'before_widget', and 'after_widget'.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public function widget( $args, $instance ) {
		if ( self::is_jetpack() &&
			/** This filter is documented in modules/contact-form/grunion-contact-form.php */
			false === apply_filters( 'jetpack_auto_fill_logged_in_user', false )
		) {
			$subscribe_email = '';
		} else {
			$current_user = wp_get_current_user();
			if ( ! empty( $current_user->user_email ) ) {
				$subscribe_email = esc_attr( $current_user->user_email );
			} else {
				$subscribe_email = '';
			}
		}

		$stats_action = self::is_jetpack() ? 'jetpack_subscriptions' : 'follow_blog';
		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', $stats_action );

		$after_widget  = isset( $args['after_widget'] ) ? $args['after_widget'] : '';
		$before_widget = isset( $args['before_widget'] ) ? $args['before_widget'] : '';
		$instance      = wp_parse_args( (array) $instance, $this->defaults() );

		echo $before_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		++self::$instance_count;

		self::render_widget_title( $args, $instance );

		self::render_widget_status_messages( $instance );

		self::render_widget_subscription_form( $args, $instance, $subscribe_email );

		echo "\n" . $after_widget; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Prints the widget's title. If show_only_email_and_button is true, we will not show a title.
	 *
	 * @param array $args Display arguments including 'before_title', 'after_title', 'before_widget', and 'after_widget'.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public static function render_widget_title( $args, $instance ) {
		$show_only_email_and_button = $instance['show_only_email_and_button'];
		$before_title               = isset( $args['before_title'] ) ? $args['before_title'] : '';
		$after_title                = isset( $args['after_title'] ) ? $args['after_title'] : '';
		if ( self::is_wpcom() && ! $show_only_email_and_button ) {
			if ( self::is_current_user_subscribed() ) {
				if ( ! empty( $instance['title_following'] ) ) {
					echo $before_title . '<label for="subscribe-field' . ( self::$instance_count > 1 ? '-' . self::$instance_count : '' ) . '">' . esc_attr( $instance['title_following'] ) . '</label>' . $after_title . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				}
			} elseif ( ! empty( $instance['title'] ) ) {
				echo $before_title . '<label for="subscribe-field' . ( self::$instance_count > 1 ? '-' . self::$instance_count : '' ) . '">' . $instance['title'] . '</label>' . $after_title . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			}
		}

		if ( self::is_jetpack() && empty( $instance['show_only_email_and_button'] ) ) {
			echo $args['before_title'] . $instance['title'] . $args['after_title'] . "\n"; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}
	}

	/**
	 * Prints the subscription block's status messages after someone has attempted to subscribe.
	 * Either a success message or an error message.
	 *
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public static function render_widget_status_messages( $instance ) {
		if ( self::is_jetpack() && isset( $_GET['subscribe'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-sensitive informational output.
			$success_message   = isset( $instance['success_message'] ) ? stripslashes( $instance['success_message'] ) : '';
			$subscribers_total = self::fetch_subscriber_count();

			switch ( $_GET['subscribe'] ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				case 'invalid_email':
					?>
					<p class="error"><?php esc_html_e( 'Oops! The email you used is invalid. Please try again.', 'jetpack' ); ?></p>
					<?php
					break;
				case 'opted_out':
					?>
					<p class="error">
					<?php
					printf(
						wp_kses(
							/* translators: 1: Link to Subscription Management page https://subscribe.wordpress.com/, 2: Description of this link. */
							__( 'Oops! It seems that the email you used has opted out of subscriptions. You can manage your preferences from the <a href="%1$s" title="%2$s" target="_blank">Subscriptions Manager</a>', 'jetpack' ),
							self::$allowed_html_tags_for_message
						),
						'https://subscribe.wordpress.com/',
						esc_attr__( 'Subscriptions Manager', 'jetpack' )
					);
					?>
					</p>
					<?php
					break;
				case 'already':
					?>
					<p class="error">
					<?php
					printf(
						wp_kses(
							/* translators: 1: Link to Subscription Management page https://subscribe.wordpress.com/, 2: Description of this link. */
							__( 'You have already subscribed to this site. Please check your email inbox. You can manage your preferences from the <a href="%1$s" title="%2$s" target="_blank">Subscriptions Manager</a>.', 'jetpack' ),
							self::$allowed_html_tags_for_message
						),
						'https://subscribe.wordpress.com/',
						esc_attr__( 'Subscriptions Manager', 'jetpack' )
					);
					?>
										</p>
					<?php
					break;
				case 'many_pending_subs':
					?>
					<p class="error">
						<?php
						printf(
							wp_kses(
								/* translators: 1: Link to Subscription Management page https://subscribe.wordpress.com/, 2: Description of this link */
								__( 'Oops! It seems you have several subscriptions pending confirmation. You can confirm or unsubscribe some from the <a href="%1$s" title="%2$s" target="_blank" rel="noopener noreferrer">Subscriptions Manager</a> before adding more.', 'jetpack' ),
								self::$allowed_html_tags_for_message
							),
							'https://subscribe.wordpress.com/',
							esc_attr__( 'Subscriptions Manager', 'jetpack' )
						);
						?>
					</p>
					<?php
					break;
				case 'pending':
					?>
					<p class="error">
						<?php
						printf(
							wp_kses(
								/* translators: 1: Link to Subscription Management page https://subscribe.wordpress.com/, 2: Description of this link */
								__( 'It seems you already tried to subscribe with this email, but have not confirmed from the email link we sent. Please check your email inbox to confirm or you can manage your preferences from the <a href="%1$s" title="%2$s" target="_blank" rel="noopener noreferrer">Subscriptions Manager</a>.', 'jetpack' ),
								self::$allowed_html_tags_for_message
							),
							'https://subscribe.wordpress.com/',
							esc_attr__( 'Subscriptions Manager', 'jetpack' )
						);
						?>
					</p>
					<?php
					break;
				case 'success':
					?>
					<div class="success"><?php echo wp_kses( wpautop( str_replace( '[total-subscribers]', number_format_i18n( $subscribers_total ), $success_message ) ), 'post' ); ?></div>
					<?php
					break;
				default:
					?>
					<p class="error"><?php esc_html_e( 'Oops! There was an error when subscribing. Please try again.', 'jetpack' ); ?></p>
					<?php
					break;
			endswitch;
		}

		if ( self::is_wpcom() && self::wpcom_has_status_message() ) {
			global $themecolors;
			$message = '';

			switch ( $_GET['blogsub'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated
				case 'confirming':
					$message = __( 'Thank you! You can now check your email to confirm your subscription.', 'jetpack' );
					break;
				case 'blocked':
					$message = __( 'Sorry but this email has been blocked for this subscription. <a href="https://en.support.wordpress.com/contact/">Contact us</a> if needed.', 'jetpack' );
					break;
				case 'flooded':
					$message = __( 'Oops! It seems you have several subscriptions pending confirmation. You can confirm or unsubscribe some from the  <a href="https://subscribe.wordpress.com/">Subscriptions Manager</a> before adding more.', 'jetpack' );
					break;
				case 'spammed':
					/* translators: %s is a URL */
					$message = sprintf( __( 'Sorry but this email has been blocked. It has too many subscriptions pending confirmation. Please confirm or unsubscribe some from the  <a href="%s">Subscriptions Manager</a>.', 'jetpack' ), 'https://subscribe.wordpress.com/' );
					break;
				case 'subscribed':
					$message = __( 'Hey! You were already subscribed.', 'jetpack' );
					break;
				case 'pending':
					$message = __( 'It seems you already tried to subscribe. We just sent you another email so you can confirm the subscription.', 'jetpack' );
					break;
				case 'confirmed':
					$message = __( 'Cool! You are now subscribed. Now you can check your email for more details and how to manage the subscription.', 'jetpack' );
					break;
			}

			$border_color = isset( $themecolors['border'] ) ? " #{$themecolors['border']}" : '';

			$redirect_fragment = self::get_redirect_fragment();
			printf(
				'<div id="%1$s" class="jetpack-sub-notification">%3$s</div>',
				esc_attr( $redirect_fragment ),
				esc_attr( $border_color ),
				wp_kses_post( $message )
			);
		}
	}

	/**
	 * Generates the redirect fragment used after form submission.
	 *
	 * @param string $id is the specific id that will appear in the redirect fragment. If none is provided self::$instance_count will be used.
	 */
	protected static function get_redirect_fragment( $id = null ) {
		if ( $id === null ) {
			return 'subscribe-blog' . ( self::$instance_count > 1 ? '-' . self::$instance_count : '' );
		}

		return 'subscribe-blog-' . $id;
	}

	/**
	 * Generates the source parameter to pass to the iframe
	 *
	 * @return string the actaul post access level (see projects/plugins/jetpack/extensions/blocks/subscriptions/settings.js for the values).
	 */
	protected static function get_post_access_level() {
		$post_id = get_the_ID();
		if ( ! $post_id ) {
			return 'everybody';
		}
		require_once __DIR__ . '/../../extensions/blocks/subscriptions/constants.php';
		$meta = get_post_meta( $post_id, META_NAME_FOR_POST_LEVEL_ACCESS_SETTINGS, true );
		if ( empty( $meta ) ) {
			$meta = 'everybody';
		}
		return $meta;
	}

	/**
	 * Renders a form allowing folks to subscribe to the blog.
	 *
	 * @param array  $args Display arguments including 'before_title', 'after_title', 'before_widget', and 'after_widget'.
	 * @param array  $instance The settings for the particular instance of the widget.
	 * @param string $subscribe_email The email to use to prefill the form.
	 */
	public static function render_widget_subscription_form( $args, $instance, $subscribe_email ) {
		$show_only_email_and_button   = $instance['show_only_email_and_button'];
		$show_subscribers_total       = (bool) $instance['show_subscribers_total'];
		$subscribers_total            = self::fetch_subscriber_count();
		$subscribe_text               = empty( $instance['show_only_email_and_button'] ) ?
			stripslashes( $instance['subscribe_text'] ) :
			false;
		$referer                      = esc_url_raw( ( is_ssl() ? 'https' : 'http' ) . '://' . ( isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( $_SERVER['HTTP_HOST'] ) : '' ) . ( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '' ) );
		$source                       = 'widget';
		$widget_id                    = ! empty( $args['widget_id'] ) ? $args['widget_id'] : self::$instance_count;
		$subscribe_button             = ! empty( $instance['submit_button_text'] ) ? $instance['submit_button_text'] : $instance['subscribe_button'];
		$subscribe_placeholder        = isset( $instance['subscribe_placeholder'] ) ? stripslashes( $instance['subscribe_placeholder'] ) : '';
		$submit_button_classes        = isset( $instance['submit_button_classes'] ) ? 'wp-block-button__link ' . $instance['submit_button_classes'] : 'wp-block-button__link';
		$submit_button_styles         = isset( $instance['submit_button_styles'] ) ? $instance['submit_button_styles'] : '';
		$submit_button_wrapper_styles = isset( $instance['submit_button_wrapper_styles'] ) ? $instance['submit_button_wrapper_styles'] : '';
		$email_field_classes          = isset( $instance['email_field_classes'] ) ? $instance['email_field_classes'] : '';
		$email_field_styles           = isset( $instance['email_field_styles'] ) ? $instance['email_field_styles'] : '';
		$post_access_level            = self::get_post_access_level();

		if ( self::is_wpcom() && ! self::wpcom_has_status_message() ) {
			global $current_blog;

			$url     = defined( 'SUBSCRIBE_BLOG_URL' ) ? SUBSCRIBE_BLOG_URL : '';
			$form_id = self::get_redirect_fragment();
			?>

			<div class="wp-block-jetpack-subscriptions__container">
			<form
				action="<?php echo esc_url( $url ); ?>"
				method="post"
				accept-charset="utf-8"
				data-blog="<?php echo esc_attr( get_current_blog_id() ); ?>"
				data-post_access_level="<?php echo esc_attr( $post_access_level ); ?>"
				id="<?php echo esc_attr( $form_id ); ?>"
			>
				<?php
				if ( ! $show_only_email_and_button ) {
					// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo wpautop( $subscribe_text );
				}
				$email_field_id  = 'subscribe-field';
				$email_field_id .= self::$instance_count > 1
					? '-' . self::$instance_count
					: '';
				$label_field_id  = $email_field_id . '-label';
				?>
				<p id="subscribe-email">
					<label
						id="<?php echo esc_attr( $label_field_id ); ?>"
						for="<?php echo esc_attr( $email_field_id ); ?>"
						class="screen-reader-text"
					>
						<?php echo esc_html__( 'Email Address:', 'jetpack' ); ?>
					</label>

					<?php
					printf(
						'<input
							type="email"
							name="email"
							%1$s
							style="%2$s"
							placeholder="%3$s"
							value=""
							id="%4$s"
							required
						/>',
						( ! empty( $email_field_classes )
							? 'class="' . esc_attr( $email_field_classes ) . '"'
							: ''
						),
						( ! empty( $email_field_styles )
							? esc_attr( $email_field_styles )
							: 'width: 95%; padding: 1px 10px'
						),
						( empty( $subscribe_placeholder ) ? esc_attr__( 'Enter your email address', 'jetpack' ) : esc_attr( $subscribe_placeholder ) ),
						esc_attr( $email_field_id )
					);
					?>
				</p>

				<p id="subscribe-submit"
					<?php if ( ! empty( $submit_button_wrapper_styles ) ) { ?>
						style="<?php echo esc_attr( $submit_button_wrapper_styles ); ?>"
					<?php } ?>
				>
					<input type="hidden" name="action" value="subscribe"/>
					<input type="hidden" name="blog_id" value="<?php echo (int) $current_blog->blog_id; ?>"/>
					<input type="hidden" name="source" value="<?php echo esc_url( $referer ); ?>"/>
					<input type="hidden" name="sub-type" value="<?php echo esc_attr( $source ); ?>"/>
					<input type="hidden" name="redirect_fragment" value="<?php echo esc_attr( $form_id ); ?>"/>
					<?php wp_nonce_field( 'blogsub_subscribe_' . $current_blog->blog_id, '_wpnonce', false ); ?>
					<button type="submit"
						<?php if ( ! empty( $submit_button_classes ) ) { ?>
							class="<?php echo esc_attr( $submit_button_classes ); ?>"
						<?php } ?>
						<?php if ( ! empty( $submit_button_styles ) ) { ?>
							style="<?php echo esc_attr( $submit_button_styles ); ?>"
						<?php } ?>
					>
						<?php
						echo wp_kses(
							html_entity_decode( $subscribe_button, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ),
							self::$allowed_html_tags_for_submit_button
						);
						?>
					</button>
				</p>
			</form>
			<?php if ( $show_subscribers_total && $subscribers_total ) { ?>
				<div class="wp-block-jetpack-subscriptions__subscount">
					<?php
					/* translators: %s: number of folks following the blog */
					echo esc_html( sprintf( _n( 'Join %s other subscriber', 'Join %s other subscribers', $subscribers_total, 'jetpack' ), number_format_i18n( $subscribers_total ) ) );
					?>
				</div>
			<?php } ?>
			</div>
			<?php
		}

		if ( self::is_jetpack() ) {
			/**
			 * Filter the subscription form's ID prefix.
			 *
			 * @module subscriptions
			 *
			 * @since 2.7.0
			 *
			 * @param string subscribe-field Subscription form field prefix.
			 * @param int $widget_id Widget ID.
			 */
			$subscribe_field_id = apply_filters( 'subscribe_field_id', 'subscribe-field', $widget_id );

			$form_id = self::get_redirect_fragment( $widget_id );
			?>
			<div class="wp-block-jetpack-subscriptions__container">
			<form action="#" method="post" accept-charset="utf-8" id="<?php echo esc_attr( $form_id ); ?>"
				data-blog="<?php echo esc_attr( \Jetpack_Options::get_option( 'id' ) ); ?>"
				data-post_access_level="<?php echo esc_attr( $post_access_level ); ?>" >
				<?php
				if ( $subscribe_text && ( ! isset( $_GET['subscribe'] ) || 'success' !== $_GET['subscribe'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Non-sensitive informational output.
					?>
					<div id="subscribe-text"><?php echo wp_kses( wpautop( str_replace( '[total-subscribers]', number_format_i18n( $subscribers_total ), $subscribe_text ) ), 'post' ); ?></div>
														<?php
				}

				if ( ! isset( $_GET['subscribe'] ) || 'success' !== $_GET['subscribe'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display of unsubmitted form.
					?>
					<p id="subscribe-email">
						<label id="jetpack-subscribe-label"
							class="screen-reader-text"
							for="<?php echo esc_attr( $subscribe_field_id . '-' . $widget_id ); ?>">
							<?php echo ! empty( $subscribe_placeholder ) ? esc_html( $subscribe_placeholder ) : esc_html__( 'Email Address:', 'jetpack' ); ?>
						</label>
						<input type="email" name="email" required="required"
							<?php if ( ! empty( $email_field_classes ) ) { ?>
								class="<?php echo esc_attr( $email_field_classes ); ?> required"
							<?php } ?>
							<?php if ( ! empty( $email_field_styles ) ) { ?>
								style="<?php echo esc_attr( $email_field_styles ); ?>"
							<?php } ?>
							value="<?php echo esc_attr( $subscribe_email ); ?>"
							id="<?php echo esc_attr( $subscribe_field_id . '-' . $widget_id ); ?>"
							placeholder="<?php echo esc_attr( $subscribe_placeholder ); ?>"
						/>
					</p>

					<p id="subscribe-submit"
						<?php if ( ! empty( $submit_button_wrapper_styles ) ) { ?>
							style="<?php echo esc_attr( $submit_button_wrapper_styles ); ?>"
						<?php } ?>
					>
						<input type="hidden" name="action" value="subscribe"/>
						<input type="hidden" name="source" value="<?php echo esc_url( $referer ); ?>"/>
						<input type="hidden" name="sub-type" value="<?php echo esc_attr( $source ); ?>"/>
						<input type="hidden" name="redirect_fragment" value="<?php echo esc_attr( $form_id ); ?>"/>
						<?php
						if ( is_user_logged_in() ) {
							wp_nonce_field( 'blogsub_subscribe_' . get_current_blog_id(), '_wpnonce', false );
						}
						?>
						<button type="submit"
							<?php if ( ! empty( $submit_button_classes ) ) { ?>
								class="<?php echo esc_attr( $submit_button_classes ); ?>"
							<?php } ?>
							<?php if ( ! empty( $submit_button_styles ) ) { ?>
								style="<?php echo esc_attr( $submit_button_styles ); ?>"
							<?php } ?>
							name="jetpack_subscriptions_widget"
						>
							<?php
							echo wp_kses(
								html_entity_decode( $subscribe_button, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401 ),
								self::$allowed_html_tags_for_submit_button
							);
							?>
						</button>
					</p>
				<?php } ?>
			</form>
			<?php if ( $show_subscribers_total && 0 < $subscribers_total ) { ?>
				<div class="wp-block-jetpack-subscriptions__subscount">
					<?php
					/* translators: %s: number of folks following the blog */
					echo esc_html( sprintf( _n( 'Join %s other subscriber', 'Join %s other subscribers', $subscribers_total, 'jetpack' ), number_format_i18n( $subscribers_total ) ) );
					?>
				</div>
			<?php } ?>
			</div>
			<?php
		}
	}

	/**
	 * Determines if the current user is subscribed to the blog.
	 *
	 * @return bool Is the person already subscribed.
	 */
	public static function is_current_user_subscribed() {
		$subscribed = isset( $_GET['subscribe'] ) && 'success' === $_GET['subscribe']; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( self::is_wpcom() && class_exists( 'Blog_Subscription' ) && class_exists( 'Blog_Subscriber' ) ) {
			$subscribed = is_user_logged_in() && Blog_Subscription::is_subscribed( new Blog_Subscriber() );
		}

		return $subscribed;
	}

	/**
	 * Is this script running in the wordpress.com environment?
	 *
	 * @return bool
	 */
	public static function is_wpcom() {
		return defined( 'IS_WPCOM' ) && IS_WPCOM;
	}

	/**
	 * Is this script running in a self-hosted environment?
	 *
	 * @return bool
	 */
	public static function is_jetpack() {
		return ! self::is_wpcom();
	}

	/**
	 * Used to determine if there is a valid status slug within the wordpress.com environment.
	 *
	 * @return bool
	 */
	public static function wpcom_has_status_message() {
		return isset( $_GET['blogsub'] ) && // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			in_array(
				$_GET['blogsub'], // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				array(
					'confirming',
					'blocked',
					'flooded',
					'spammed',
					'subscribed',
					'pending',
					'confirmed',
				),
				true
			);
	}

	/**
	 * Determine the amount of folks currently subscribed to the blog.
	 *
	 * @return int
	 */
	public static function fetch_subscriber_count() {
		$subs_count = 0;
		if ( self::is_jetpack() ) {
			$cache_key  = 'wpcom_subscribers_total';
			$subs_count = get_transient( $cache_key );
			if ( false === $subs_count || 'failed' === $subs_count['status'] ) {
				$xml = new Jetpack_IXR_Client();
				$xml->query( 'jetpack.fetchSubscriberCount' );

				if ( $xml->isError() ) { // If we get an error from .com, set the status to failed so that we will try again next time the data is requested.

					$subs_count = array(
						'status'  => 'failed',
						'code'    => $xml->getErrorCode(),
						'message' => $xml->getErrorMessage(),
						'value'   => ( isset( $subs_count['value'] ) ) ? $subs_count['value'] : 0,
					);
				} else {
					$subs_count = array(
						'status' => 'success',
						'value'  => $xml->getResponse(),
					);
				}
				set_transient( $cache_key, $subs_count, 3600 ); // Try to cache the result for at least 1 hour.
			}
			return $subs_count['value'];
		}

		if ( self::is_wpcom() ) {
			$subs_count = wpcom_reach_total_for_blog();
			return $subs_count;
		}
	}

	/**
	 * Updates a particular instance of a widget when someone saves it in wp-admin.
	 *
	 * @param array $new_instance New widget instance settings.
	 * @param array $old_instance Old widget instance settings.
	 *
	 * @return array
	 */
	public function update( $new_instance, $old_instance ) {
		$instance = $old_instance;

		if ( self::is_jetpack() ) {
			$instance['title']                 = wp_kses( stripslashes( $new_instance['title'] ), array() );
			$instance['subscribe_placeholder'] = wp_kses( stripslashes( $new_instance['subscribe_placeholder'] ), array() );
			$instance['subscribe_button']      = wp_kses( stripslashes( $new_instance['subscribe_button'] ), array() );
			$instance['success_message']       = wp_kses( stripslashes( $new_instance['success_message'] ), array() );
		}

		if ( self::is_wpcom() ) {
			$instance['title']               = wp_strip_all_tags( stripslashes( $new_instance['title'] ) );
			$instance['title_following']     = wp_strip_all_tags( stripslashes( $new_instance['title_following'] ) );
			$instance['subscribe_logged_in'] = wp_filter_post_kses( stripslashes( $new_instance['subscribe_logged_in'] ) );
			$instance['subscribe_button']    = wp_strip_all_tags( stripslashes( $new_instance['subscribe_button'] ) );
		}

		$instance['show_subscribers_total']     = isset( $new_instance['show_subscribers_total'] ) && $new_instance['show_subscribers_total'];
		$instance['show_only_email_and_button'] = isset( $new_instance['show_only_email_and_button'] ) && $new_instance['show_only_email_and_button'];
		$instance['subscribe_text']             = wp_filter_post_kses( stripslashes( $new_instance['subscribe_text'] ) );

		return $instance;
	}

	/**
	 * The default args for rendering a subscription form.
	 *
	 * @return array
	 */
	public static function defaults() {
		$defaults = array(
			'show_subscribers_total'     => true,
			'show_only_email_and_button' => false,
			'include_social_followers'   => true,
		);

		$defaults['title']                 = esc_html__( 'Subscribe to Blog via Email', 'jetpack' );
		$defaults['subscribe_text']        = esc_html__( 'Enter your email address to subscribe to this blog and receive notifications of new posts by email.', 'jetpack' );
		$defaults['subscribe_placeholder'] = esc_html__( 'Email Address', 'jetpack' );
		$defaults['subscribe_button']      = esc_html__( 'Subscribe', 'jetpack' );
		$defaults['success_message']       = esc_html__( "Success! An email was just sent to confirm your subscription. Please find the email now and click 'Confirm Follow' to start subscribing.", 'jetpack' );

		return $defaults;
	}

	/**
	 * Renders the widget's options form in wp-admin.
	 *
	 * @param array $instance Widget instance.
	 */
	public function form( $instance ) {
		$instance               = wp_parse_args( (array) $instance, $this->defaults() );
		$show_subscribers_total = checked( $instance['show_subscribers_total'], true, false );

		if ( self::is_wpcom() ) {
			$title               = esc_attr( stripslashes( $instance['title'] ) );
			$title_following     = esc_attr( stripslashes( $instance['title_following'] ) );
			$subscribe_text      = esc_attr( stripslashes( $instance['subscribe_text'] ) );
			$subscribe_logged_in = esc_attr( stripslashes( $instance['subscribe_logged_in'] ) );
			$subscribe_button    = esc_attr( stripslashes( $instance['subscribe_button'] ) );
			$subscribers_total   = self::fetch_subscriber_count();
		}

		if ( self::is_jetpack() ) {
			$title                 = stripslashes( $instance['title'] );
			$subscribe_text        = stripslashes( $instance['subscribe_text'] );
			$subscribe_placeholder = stripslashes( $instance['subscribe_placeholder'] );
			$subscribe_button      = stripslashes( $instance['subscribe_button'] );
			$success_message       = stripslashes( $instance['success_message'] );
			$subscribers_total     = self::fetch_subscriber_count();
		}

		if ( self::is_wpcom() ) :
			?>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
					<?php esc_html_e( 'Widget title for non-followers:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text"
						value="<?php echo esc_attr( $title ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'title_following' ) ); ?>">
					<?php esc_html_e( 'Widget title for followers:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title_following' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'title_following' ) ); ?>" type="text"
						value="<?php echo esc_attr( $title_following ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_logged_in' ) ); ?>">
					<?php esc_html_e( 'Optional text to display to logged in WordPress.com users:', 'jetpack' ); ?>
					<textarea style="width: 95%" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_logged_in' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_logged_in' ) ); ?>"
						type="text"><?php echo esc_html( $subscribe_logged_in ); ?></textarea>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_text' ) ); ?>">
					<?php esc_html_e( 'Optional text to display to non-WordPress.com users:', 'jetpack' ); ?>
					<textarea style="width: 95%" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_text' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_text' ) ); ?>"
						type="text"><?php echo esc_html( $subscribe_text ); ?></textarea>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_button' ) ); ?>">
					<?php esc_html_e( 'Follow Button Text:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_button' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_button' ) ); ?>" type="text"
						value="<?php echo esc_attr( $subscribe_button ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'show_subscribers_total' ) ); ?>">
					<input type="checkbox" id="<?php echo esc_attr( $this->get_field_id( 'show_subscribers_total' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'show_subscribers_total' ) ); ?>"
						value="1"<?php echo esc_attr( $show_subscribers_total ); ?> />
					<?php
					/* translators: %s: Number of followers. */
					echo esc_html( sprintf( _n( 'Show total number of followers? (%s follower)', 'Show total number of followers? (%s followers)', $subscribers_total, 'jetpack' ), number_format_i18n( $subscribers_total ) ) );
					?>
				</label>
			</p>
			<?php
		endif;

		if ( self::is_jetpack() ) :
			?>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>">
					<?php esc_html_e( 'Widget title:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text"
						value="<?php echo esc_attr( $title ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_text' ) ); ?>">
					<?php esc_html_e( 'Optional text to display to your readers:', 'jetpack' ); ?>
					<textarea class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_text' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_text' ) ); ?>"
						rows="3"><?php echo esc_html( $subscribe_text ); ?></textarea>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_placeholder' ) ); ?>">
					<?php esc_html_e( 'Subscribe Placeholder:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_placeholder' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_placeholder' ) ); ?>" type="text"
						value="<?php echo esc_attr( $subscribe_placeholder ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'subscribe_button' ) ); ?>">
					<?php esc_html_e( 'Subscribe Button:', 'jetpack' ); ?>
					<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'subscribe_button' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'subscribe_button' ) ); ?>" type="text"
						value="<?php echo esc_attr( $subscribe_button ); ?>"/>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'success_message' ) ); ?>">
					<?php esc_html_e( 'Success Message Text:', 'jetpack' ); ?>
					<textarea class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'success_message' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'success_message' ) ); ?>"
						rows="5"><?php echo esc_html( $success_message ); ?></textarea>
				</label>
			</p>
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'show_subscribers_total' ) ); ?>">
					<input type="checkbox" id="<?php echo esc_attr( $this->get_field_id( 'show_subscribers_total' ) ); ?>"
						name="<?php echo esc_attr( $this->get_field_name( 'show_subscribers_total' ) ); ?>"
						value="1"<?php echo esc_attr( $show_subscribers_total ); ?> />
					<?php
					/* translators: %s: Number of subscribers. */
					echo esc_html( sprintf( _n( 'Show total number of subscribers? (%s subscriber)', 'Show total number of subscribers? (%s subscribers)', $subscribers_total, 'jetpack' ), $subscribers_total ) );
					?>
				</label>
			</p>
			<?php
		endif;
	}
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM && function_exists( 'class_alias' ) ) {
	class_alias( 'Jetpack_Subscriptions_Widget', 'Blog_Subscription_Widget' );
}

/**
 * Classname / shortcode tag to use for the Subscriptions widget.
 *
 * @return string
 */
function get_jetpack_blog_subscriptions_widget_classname() {
	return ( defined( 'IS_WPCOM' ) && IS_WPCOM ) ?
		'Blog_Subscription_Widget' :
		'Jetpack_Subscriptions_Widget';
}

/**
 * Subscriptions widget form HTML output.
 *
 * @param array $instance Widget instance data.
 */
function jetpack_do_subscription_form( $instance ) {
	if ( empty( $instance ) || ! is_array( $instance ) ) {
		$instance = array();
	}

	if ( empty( $instance['show_subscribers_total'] ) || 'false' === $instance['show_subscribers_total'] ) {
		$instance['show_subscribers_total'] = false;
	} else {
		$instance['show_subscribers_total'] = true;
	}

	// the default behavior is to include the social followers
	if ( empty( $instance['include_social_followers'] ) || 'true' === $instance['include_social_followers'] ) {
		$instance['include_social_followers'] = true;
	} else {
		$instance['include_social_followers'] = false;
	}

	$show_only_email_and_button = isset( $instance['show_only_email_and_button'] ) ? $instance['show_only_email_and_button'] : false;
	$submit_button_text         = isset( $instance['submit_button_text'] ) ? $instance['submit_button_text'] : '';

	// Build up a string with the submit button's classes and styles and set it on the instance.
	$submit_button_classes        = isset( $instance['submit_button_classes'] ) ? $instance['submit_button_classes'] : '';
	$email_field_classes          = isset( $instance['email_field_classes'] ) ? $instance['email_field_classes'] : '';
	$style                        = '';
	$submit_button_styles         = '';
	$submit_button_wrapper_styles = '';
	$email_field_styles           = '';
	$success_message              = '';

	if ( isset( $instance['custom_background_button_color'] ) && 'undefined' !== $instance['custom_background_button_color'] ) {
		$submit_button_styles .= 'background: ' . $instance['custom_background_button_color'] . '; ';
	}
	if ( isset( $instance['custom_text_button_color'] ) && 'undefined' !== $instance['custom_text_button_color'] ) {
		$submit_button_styles .= 'color: ' . $instance['custom_text_button_color'] . '; ';
	}
	if ( isset( $instance['custom_button_width'] ) && 'undefined' !== $instance['custom_button_width'] ) {
		$submit_button_wrapper_styles .= 'width: ' . $instance['custom_button_width'] . '; ';
		$submit_button_wrapper_styles .= 'max-width: 100%; ';

		// Account for custom margins on inline forms.
		if (
			! empty( $instance['custom_spacing'] ) &&
			! ( isset( $instance['button_on_newline'] ) && 'true' === $instance['button_on_newline'] )
		) {
			$submit_button_styles .= 'width: calc(100% - ' . $instance['custom_spacing'] . 'px); ';
		} else {
			$submit_button_styles .= 'width: 100%; ';
		}
	}

	if ( isset( $instance['custom_font_size'] ) && 'undefined' !== $instance['custom_font_size'] ) {
		$style  = 'font-size: ' . $instance['custom_font_size'];
		$style .= is_numeric( $instance['custom_font_size'] ) ? 'px; ' : '; '; // Handle deprecated numeric font size values.

		$submit_button_styles .= $style;
		$email_field_styles   .= $style;
	}
	if ( isset( $instance['custom_padding'] ) && 'undefined' !== $instance['custom_padding'] ) {
		$style = 'padding: ' .
			$instance['custom_padding'] . 'px ' .
			round( $instance['custom_padding'] * 1.5 ) . 'px ' .
			$instance['custom_padding'] . 'px ' .
			round( $instance['custom_padding'] * 1.5 ) . 'px; ';

		$submit_button_styles .= $style;
		$email_field_styles   .= $style;
	}

	$button_spacing = 0;
	if ( ! empty( $instance['custom_spacing'] ) ) {
		$button_spacing = $instance['custom_spacing'];
	}
	if ( isset( $instance['button_on_newline'] ) && 'true' === $instance['button_on_newline'] ) {
		$submit_button_styles .= 'margin-top: ' . $button_spacing . 'px; ';
	} else {
		$submit_button_styles .= 'margin: 0px; '; // Reset Safari's 2px default margin for buttons affecting input and button union
		$submit_button_styles .= 'margin-left: ' . $button_spacing . 'px; ';
	}

	if ( isset( $instance['custom_border_radius'] ) && 'undefined' !== $instance['custom_border_radius'] ) {
		$style                 = 'border-radius: ' . $instance['custom_border_radius'] . 'px; ';
		$submit_button_styles .= $style;
		$email_field_styles   .= $style;
	}
	if ( isset( $instance['custom_border_weight'] ) && 'undefined' !== $instance['custom_border_weight'] ) {
		$style                 = 'border-width: ' . $instance['custom_border_weight'] . 'px; ';
		$submit_button_styles .= $style;
		$email_field_styles   .= $style;
	}
	if ( isset( $instance['custom_border_color'] ) && 'undefined' !== $instance['custom_border_color'] ) {
		$style =
			'border-color: ' . $instance['custom_border_color'] . '; ' .
			'border-style: solid;';

		$submit_button_styles .= $style;
		$email_field_styles   .= $style;
	}
	if ( isset( $instance['success_message'] ) && 'undefined' !== $instance['success_message'] ) {
		$success_message = wp_kses( stripslashes( $instance['success_message'] ), array() );
	}

	$instance = shortcode_atts(
		Jetpack_Subscriptions_Widget::defaults(),
		$instance,
		'jetpack_subscription_form'
	);

	// These must come after the call to shortcode_atts().
	$instance['submit_button_text']         = $submit_button_text;
	$instance['show_only_email_and_button'] = $show_only_email_and_button;
	if ( ! empty( $submit_button_classes ) ) {
		$instance['submit_button_classes'] = $submit_button_classes;
	}
	if ( ! empty( $email_field_classes ) ) {
		$instance['email_field_classes'] = $email_field_classes;
	}

	if ( ! empty( $submit_button_styles ) ) {
		$instance['submit_button_styles'] = trim( $submit_button_styles );
	}
	if ( ! empty( $submit_button_wrapper_styles ) ) {
		$instance['submit_button_wrapper_styles'] = trim( $submit_button_wrapper_styles );
	}
	if ( ! empty( $email_field_styles ) ) {
		$instance['email_field_styles'] = trim( $email_field_styles );
	}
	if ( ! empty( $success_message ) ) {
		$instance['success_message'] = trim( $success_message );
	}

	$args = array(
		'before_widget' => '<div class="jetpack_subscription_widget">',
	);
	ob_start();
	the_widget( get_jetpack_blog_subscriptions_widget_classname(), $instance, $args );
	$output = ob_get_clean();

	return $output;
}

add_shortcode( 'jetpack_subscription_form', 'jetpack_do_subscription_form' );
add_shortcode( 'blog_subscription_form', 'jetpack_do_subscription_form' );

/**
 * Register the Subscriptions widget.
 */
function jetpack_blog_subscriptions_init() {
	register_widget( get_jetpack_blog_subscriptions_widget_classname() );
}

add_action( 'widgets_init', 'jetpack_blog_subscriptions_init' );

/**
 * Sets the default value for `subscription_options` site option.
 *
 * This default value is available across Simple, Atomic and Jetpack sites,
 * including the /sites/$site/settings endpoint.
 *
 * @param array  $default Default `subscription_options` array.
 * @param string $option Option name.
 * @param bool   $passed_default Whether `get_option()` passed a default value.
 *
 * @return array Default value of `subscription_options`.
 */
function subscription_options_fallback( $default, $option, $passed_default ) {
	if ( $passed_default ) {
		return $default;
	}

	$site_url    = get_home_url();
	$display_url = preg_replace( '(^https?://)', '', untrailingslashit( $site_url ) );

	return array(
		/* translators: Both %1$s and %2$s is site address */
		'invitation'     => sprintf( __( "Howdy,\nYou recently subscribed to <a href='%1\$s'>%2\$s</a> and we need to verify the email you provided. Once you confirm below, you'll be able to receive and read new posts.\n\nIf you believe this is an error, ignore this message and nothing more will happen.", 'jetpack' ), $site_url, $display_url ),
		'comment_follow' => __( "Howdy.\n\nYou recently followed one of my posts. This means you will receive an email when new comments are posted.\n\nTo activate, click confirm below. If you believe this is an error, ignore this message and we'll never bother you again.", 'jetpack' ),
	);
}

add_filter( 'default_option_subscription_options', 'subscription_options_fallback', 10, 3 );
