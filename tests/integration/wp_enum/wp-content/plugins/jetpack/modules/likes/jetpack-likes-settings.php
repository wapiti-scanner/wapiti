<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Sync\Settings;

/**
 * Jetpack likes settings class.
 */
class Jetpack_Likes_Settings {

	/**
	 * False if running on WPCOM Simple
	 *
	 * @var bool
	 */
	public $in_jetpack;

	/**
	 * Constructor function.
	 */
	public function __construct() {
		$this->in_jetpack = ! ( defined( 'IS_WPCOM' ) && IS_WPCOM );
	}

	/**
	 * Replaces the "Sharing" title for the post screen metabox with "Likes and Shares"
	 */
	public function add_likes_to_sharing_meta_box_title() {
		return __( 'Likes and Shares', 'jetpack' );
	}

	/**
	 * Adds a metabox to the post screen if the sharing one doesn't currently exist.
	 */
	public function add_meta_box() {
		if (
			/**
			 * Allow disabling of the Likes metabox on the post editor screen.
			 *
			 * @module likes
			 *
			 * @since 2.2.0
			 *
			 * @param bool false Should the Likes metabox be disabled? Default to false.
			 */
		apply_filters( 'post_flair_disable', false )
		) {
			return;
		}

		$post_types = get_post_types( array( 'public' => true ) );
		/**
		 * Filters the Likes metabox title.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param string Likes metabox title. Default to "Likes".
		 */
		$title = apply_filters( 'likes_meta_box_title', __( 'Likes', 'jetpack' ) );
		foreach ( $post_types as $post_type ) {
			add_meta_box( 'likes_meta', $title, array( $this, 'meta_box_content' ), $post_type, 'side', 'default', array( '__back_compat_meta_box' => true ) );
		}
	}

	/**
	 * Shows the likes option in the post screen metabox.
	 *
	 * @param object $post - the post object.
	 */
	public function meta_box_content( $post ) {
		$post_id         = ! empty( $post->ID ) ? (int) $post->ID : get_the_ID();
		$checked         = true;
		$disabled        = ! $this->is_enabled_sitewide();
		$switched_status = get_post_meta( $post_id, 'switch_like_status', true );

		if ( $disabled && empty( $switched_status ) || ! $disabled && $switched_status === '0' ) {
			$checked = false;
		}

		/**
		 * Fires before the Likes meta box content in the post editor.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param WP_Post|array|null $post Post data.
		 */
		do_action( 'start_likes_meta_box_content', $post );
		?>

		<p>
			<label for="wpl_enable_post_likes">
				<input type="checkbox" name="wpl_enable_post_likes" id="wpl_enable_post_likes" value="1" <?php checked( $checked ); ?>>
				<?php esc_html_e( 'Show likes.', 'jetpack' ); ?>
			</label>
			<input type="hidden" name="wpl_like_status_hidden" value="1" />
			<?php wp_nonce_field( 'likes-and-shares', '_likesharenonce' ); ?>
		</p> 
		<?php
		/**
		 * Fires after the Likes meta box content in the post editor.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param WP_Post|array|null $post Post data.
		 */
		do_action( 'end_likes_meta_box_content', $post );
	}

	/**
	 * Returns the current state of the "WordPress.com Likes are" option.
	 *
	 * @return boolean true if enabled sitewide, false if not
	 */
	public function is_enabled_sitewide() {
		/**
		 * Filters whether Likes are enabled by default on all posts.
		 * true if enabled sitewide, false if not.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $option Are Likes enabled sitewide.
		 */
		return (bool) apply_filters( 'wpl_is_enabled_sitewide', ! Jetpack_Options::get_option_and_ensure_autoload( 'disabled_likes', 0 ) );
	}

	/**
	 * Handle meta box saving.
	 *
	 * @param int $post_id - the post ID.
	 */
	public function meta_box_save( $post_id ) {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return $post_id;
		}

		if ( empty( $_POST['wpl_like_status_hidden'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- we're not changing anything on the site.
			return $post_id;
		}

		if ( ! isset( $_POST['_likesharenonce'] ) || ! wp_verify_nonce( $_POST['_likesharenonce'], 'likes-and-shares' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WordPress core doesn't unslash or verify nonces either.
			return $post_id;
		}

		// Record sharing disable. Only needs to be done for WPCOM.
		if ( ! $this->in_jetpack ) {
			if ( isset( $_POST['post_type'] ) && in_array( $_POST['post_type'], get_post_types( array( 'public' => true ) ), true ) ) {
				if ( ! isset( $_POST['wpl_enable_post_sharing'] ) ) {
					update_post_meta( $post_id, 'sharing_disabled', 1 );
				} else {
					delete_post_meta( $post_id, 'sharing_disabled' );
				}
			}
		}

		if ( 'post' === $_POST['post_type'] ) {
			if ( ! current_user_can( 'edit_post', $post_id ) ) {
				return $post_id;
			}
		}

		// Record a change in like status for this post - only if it contradicts the
		// site like setting. If it doesn't contradict, then we delete the new individual status.
		if ( ! $this->is_enabled_sitewide() && ! empty( $_POST['wpl_enable_post_likes'] ) ) {
			// Likes turned on for individual posts. User wants to add the button to a single post.
			update_post_meta( $post_id, 'switch_like_status', 1 );
		} elseif ( $this->is_enabled_sitewide() && empty( $_POST['wpl_enable_post_likes'] ) ) {
			// Likes turned on for all posts. User wants to remove the button from a single post.
			update_post_meta( $post_id, 'switch_like_status', 0 );
		} elseif (
		( ! $this->is_enabled_sitewide() && empty( $_POST['wpl_enable_post_likes'] ) ) ||
		( $this->is_enabled_sitewide() && ! empty( $_POST['wpl_enable_post_likes'] ) )
		) {
			// User wants to update the likes button status for an individual post, but the new status
			// is the same as if they're asking for the default behavior according to the current Likes setting.
			// So we delete the meta.
			delete_post_meta( $post_id, 'switch_like_status' );
		}

		return $post_id;
	}

	/**
	 * WordPress.com: Metabox option for sharing (sharedaddy will handle this on the JP blog).
	 *
	 * @param object $post - the post object.
	 */
	public function sharing_meta_box_content( $post ) {
		$post_id  = ! empty( $post->ID ) ? (int) $post->ID : get_the_ID();
		$disabled = get_post_meta( $post_id, 'sharing_disabled', true );
		?>
		<p>
			<label for="wpl_enable_post_sharing">
				<input type="checkbox" name="wpl_enable_post_sharing" id="wpl_enable_post_sharing" value="1" <?php checked( ! $disabled ); ?>>
				<?php esc_html_e( 'Show sharing buttons.', 'jetpack' ); ?>
			</label>
			<input type="hidden" name="wpl_sharing_status_hidden" value="1" />
		</p> 
		<?php
	}

	/**
	 * Adds the 'sharing' menu to the settings menu.
	 * Only ran if sharedaddy and publicize are not already active.
	 */
	public function sharing_menu() {
		add_submenu_page( 'options-general.php', esc_html__( 'Sharing Settings', 'jetpack' ), esc_html__( 'Sharing', 'jetpack' ), 'manage_options', 'sharing', array( $this, 'sharing_page' ) );
	}

	/**
	 * Provides a sharing page with the sharing_global_options hook
	 * so we can display the setting.
	 * Only ran if sharedaddy and publicize are not already active.
	 */
	public function sharing_page() {
		$this->updated_message();
		?>
		<div class="wrap">
			<div class="icon32" id="icon-options-general"><br /></div>
			<h1><?php esc_html_e( 'Sharing Settings', 'jetpack' ); ?></h1>
			<?php
			/** This action is documented in modules/sharedaddy/sharing.php */
			do_action( 'pre_admin_screen_sharing' );
			?>
			<?php $this->sharing_block(); ?>
		</div> 
		<?php
	}

	/**
	 * Returns the settings have been saved message.
	 */
	public function updated_message() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- ignoring since we are just displaying that the settings have been saved and not making  any other changes to the site.
		if ( isset( $_GET['update'] ) && 'saved' === $_GET['update'] ) {
			echo '<div class="updated"><p>' . esc_html__( 'Settings have been saved', 'jetpack' ) . '</p></div>';
		}
	}

	/**
	 * Returns just the "sharing buttons" w/ like option block, so it can be inserted into different sharing page contexts
	 */
	public function sharing_block() {
		?>
		<h2><?php esc_html_e( 'Sharing Buttons', 'jetpack' ); ?></h2>
		<form method="post" action="">
			<table class="form-table">
				<tbody>
				<?php
				/** This action is documented in modules/sharedaddy/sharing.php */
				do_action( 'sharing_global_options' );
				?>
				</tbody>
			</table>

			<p class="submit">
			<input type="submit" name="submit" class="button-primary" value="<?php esc_attr_e( 'Save Changes', 'jetpack' ); ?>" />
			<?php wp_nonce_field( 'sharing-options' ); ?>
		</form> 
		<?php
	}

	/**
	 * Are likes enabled for this post?
	 *
	 * @param int $post_id - the post ID.
	 * @return bool
	 */
	public function is_post_likeable( $post_id = 0 ) {
		$post = get_post( $post_id );
		if ( ! $post || is_wp_error( $post ) ) {
			return false;
		}

		$sitewide_likes_enabled = (bool) $this->is_enabled_sitewide();
		$post_likes_switched    = get_post_meta( $post->ID, 'switch_like_status', true );

		/*
		 * On WPCOM, headstart was inserting bad data for post_likes_switched.
		 * it was wrapping the boolean value in an array. The array is always truthy regardless of its contents.
		 * There was another bug where truthy values were ignored if the global like setting was false.
		 * So in effect, the values for headstart never had an inpact.
		 * Delete the $post_likes_switched flag in this case in order to keep the behaviour as it was.
		 */
		if ( is_array( $post_likes_switched ) ) {
			$post_likes_switched = null;
		}

		/*
		 * on WPCOM, we need to look at post edit date so we don't break old posts
		 * if post edit date predates this code, stick with the former (buggy) behavior
		 * see: p7DVsv-64H-p2
		 */
		$last_modified_time = strtotime( $post->post_modified_gmt );

		$behavior_was_changed_at = strtotime( '2019-02-22 00:40:42' );

		if ( $this->in_jetpack || $last_modified_time > $behavior_was_changed_at ) {
			/*
			 * the new and improved behavior on Jetpack and recent WPCOM posts:
			 * $post_likes_switched is empty to follow site setting,
			 * 0 if we want likes disabled, 1 if we want likes enabled.
			 */
			return $post_likes_switched || ( $sitewide_likes_enabled && $post_likes_switched !== '0' );
		}

		// implicit else (old behavior): $post_likes_switched simply inverts the global setting.
		return ( (bool) $post_likes_switched ) xor $sitewide_likes_enabled;
	}

	/**
	 * Is the like button itself visible (as opposed to the reblog button)
	 *
	 * If called from within The Loop or if called with a $post_id set, then the post will be checked.
	 * Otherwise the sitewide setting will be used.
	 *
	 * @param int $post_id The ID of the post being rendered. Defaults to the current post if called from within The Loop.
	 * @return bool
	 */
	public function is_likes_button_visible( $post_id = 0 ) {
		if ( in_the_loop() || $post_id ) {
			// If in The Loop, is_post_likeable will check the current post.
			return $this->is_post_likeable( $post_id );
		} else {
			// Otherwise, check and see if likes are enabled sitewide.
			return $this->is_enabled_sitewide();
		}
	}

	/**
	 * Are likes visible in this context?
	 *
	 * Some of this code was taken and modified from sharing_display() to ensure
	 * similar logic and filters apply here, too.
	 */
	public function is_likes_visible() {
		if ( Settings::is_syncing() ) {
			return false;
		}

		return $this->is_likes_button_visible() && $this->is_likes_module_enabled();
	}

	/**
	 * Apply filters to determine if the likes module itself is enabled
	 *
	 * @return bool
	 */
	public function is_likes_module_enabled() {
		global $wp_current_filter; // Used to apply 'sharing_show' filter.

		$post    = get_post();
		$enabled = true;

		// Never show on feeds or previews.
		if ( is_feed() || is_preview() ) {
			$enabled = false;
			// Not a feed or preview, so what is it?
		} else {
			if ( post_password_required() ) {
				$enabled = false;
			}

			if ( in_array( 'get_the_excerpt', (array) $wp_current_filter, true ) ) {
				$enabled = false;
			}
			// Sharing Setting Overrides ****************************************
			// Single post including custom post types.
			if ( is_single() ) {
				if ( ! $this->is_single_post_enabled( ( $post instanceof WP_Post ) ? $post->post_type : 'post' ) ) {
					$enabled = false;
				}

				// Single page.
			} elseif ( is_page() && ! is_front_page() ) {
				if ( ! $this->is_single_page_enabled() ) {
					$enabled = false;
				}

				// Attachment.
			} elseif ( is_attachment() ) {
				if ( ! $this->is_attachment_enabled() ) {
					$enabled = false;
				}

				// All other loops.
			} elseif ( ! $this->is_index_enabled() ) {
				$enabled = false;
			}
		}

		if ( $post instanceof WP_Post ) {
			// Check that the post is a public, published post.
			if ( 'attachment' === $post->post_type ) {
				$post_status = get_post_status( $post->post_parent );
			} else {
				$post_status = $post->post_status;
			}
			if ( 'publish' !== $post_status ) {
				$enabled = false;
			}
		}

		// Run through the sharing filters.
		/** This filter is documented in modules/sharedaddy/sharing-service.php */
		$enabled = apply_filters( 'sharing_show', $enabled, $post );

		/**
		 * Filters whether the Likes should be visible or not.
		 * Allows overwriting the options set in Settings > Sharing.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $enabled Should the Likes be visible?
		 */
		return (bool) apply_filters( 'wpl_is_likes_visible', $enabled );
	}

	/**
	 * Are Post Likes enabled on single posts?
	 *
	 * @param string $post_type custom post type identifier.
	 * @return bool
	 */
	public function is_single_post_enabled( $post_type = 'post' ) {
		$options = $this->get_options();
		return (bool) apply_filters(
		/**
		 * Filters whether Likes should be enabled on single posts.
		 *
		 * The dynamic part of the filter, {$post_type}, allows you to specific the post type where Likes should be enabled.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $enabled Are Post Likes enabled on single posts?
		 */
			"wpl_is_single_{$post_type}_disabled",
			(bool) in_array( $post_type, $options['show'], true )
		);
	}

	/**
	 * Get the 'disabled_likes' option from the DB of the current blog.
	 *
	 * @return array
	 */
	public function get_options() {
		$setting             = array();
		$setting['disabled'] = get_option( 'disabled_likes' );
		$sharing             = get_option( 'sharing-options', array() );

		// Default visibility settings
		if ( ! isset( $sharing['global']['show'] ) ) {
			$sharing['global']['show'] = array( 'post', 'page' );

			// Scalar check
		} elseif ( is_scalar( $sharing['global']['show'] ) ) {
			switch ( $sharing['global']['show'] ) {
				case 'posts':
					$sharing['global']['show'] = array( 'post', 'page' );
					break;
				case 'index':
					$sharing['global']['show'] = array( 'index' );
					break;
				case 'posts-index':
					$sharing['global']['show'] = array( 'post', 'page', 'index' );
					break;
			}
		}

		// Ensure it's always an array (even if not previously empty or scalar)
		$setting['show'] = ! empty( $sharing['global']['show'] ) ? (array) $sharing['global']['show'] : array();

		/**
		 * Filters where the Likes are displayed.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param array $setting Array of Likes display settings.
		 */
		return apply_filters( 'wpl_get_options', $setting );
	}

	/**
	 * Are Post Likes enabled on archive/front/search pages?
	 *
	 * @return bool
	 */
	public function is_index_enabled() {
		$options = $this->get_options();
		/**
		 * Filters whether Likes should be enabled on archive/front/search pages.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $enabled Are Post Likes enabled on archive/front/search pages?
		 */
		return (bool) apply_filters( 'wpl_is_index_disabled', (bool) in_array( 'index', $options['show'], true ) );
	}

	/**
	 * Are Post Likes enabled on single pages?
	 *
	 * @return bool
	 */
	public function is_single_page_enabled() {
		$options = $this->get_options();
		/**
		 * Filters whether Likes should be enabled on single pages.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $enabled Are Post Likes enabled on single pages?
		 */
		return (bool) apply_filters( 'wpl_is_single_page_disabled', (bool) in_array( 'page', $options['show'], true ) );
	}

	/**
	 * Are Media Likes enabled on single pages?
	 *
	 * @return bool
	 */
	public function is_attachment_enabled() {
		$options = $this->get_options();
		/**
		 * Filters whether Likes should be enabled on attachment pages.
		 *
		 * @module likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $enabled Are Post Likes enabled on attachment pages?
		 */
		return (bool) apply_filters( 'wpl_is_attachment_disabled', (bool) in_array( 'attachment', $options['show'], true ) );
	}

	/**
	 * The actual options block to be inserted into the sharing page.
	 */
	public function admin_settings_init() {
		?>
		<tr>
			<th scope="row">
				<label><?php esc_html_e( 'WordPress.com Likes are', 'jetpack' ); ?></label>
			</th>
			<td>
				<div>
					<label>
						<input type="radio" class="code" name="wpl_default" value="on" <?php checked( $this->is_enabled_sitewide(), true ); ?> />
						<?php esc_html_e( 'On for all posts', 'jetpack' ); ?>
					</label>
				</div>
				<div>
					<label>
						<input type="radio" class="code" name="wpl_default" value="off" <?php checked( $this->is_enabled_sitewide(), false ); ?> />
						<?php esc_html_e( 'Turned on per post', 'jetpack' ); ?>
					</label>
					<div>
			</td>
		</tr>
		<?php if ( ! $this->in_jetpack ) : ?>
			<tr>
				<th scope="row">
					<label><?php esc_html_e( 'WordPress.com Reblog Button', 'jetpack' ); ?></label>
				</th>
				<td>
					<div>
						<label>
							<input type="radio" class="code" name="jetpack_reblogs_enabled" value="on" <?php checked( $this->reblogs_enabled_sitewide(), true ); ?> />
							<?php esc_html_e( 'Show the Reblog button on posts', 'jetpack' ); ?>
						</label>
					</div>
					<div>
						<label>
							<input type="radio" class="code" name="jetpack_reblogs_enabled" value="off" <?php checked( $this->reblogs_enabled_sitewide(), false ); ?> />
							<?php esc_html_e( 'Don\'t show the Reblog button on posts', 'jetpack' ); ?>
						</label>
					</div>
				</td>
			</tr>
			<!-- WPCOM only: Comment Likes -->
			<?php if ( ! $this->in_jetpack ) : ?>
				<tr>
					<th scope="row">
						<label><?php esc_html_e( 'Comment Likes are', 'jetpack' ); ?></label>
					</th>
					<td>
						<div>
							<label>
								<input type="checkbox" class="code" name="jetpack_comment_likes_enabled" value="1" <?php checked( $this->is_comments_enabled(), true ); ?> />
								<?php esc_html_e( 'On for all comments', 'jetpack' ); ?>
							</label>
						</div>
					</td>
				</tr>
			<?php endif; ?>
		<?php endif; ?>
		</tbody> <?php // closes the tbody attached to sharing_show_buttons_on_row_start... ?>
		<?php
	}

	/**
	 * Returns the current state of the "WordPress.com Reblogs are" option.
	 *
	 * @return bool true if enabled sitewide, false if not
	 */
	public function reblogs_enabled_sitewide() {
		/**
		 * Filters whether Reblogs are enabled by default on all posts.
		 * true if enabled sitewide, false if not.
		 *
		 * @module likes
		 *
		 * @since 3.0.0
		 *
		 * @param bool $option Are Reblogs enabled sitewide.
		 */
		return (bool) apply_filters( 'wpl_reblogging_enabled_sitewide', ! get_option( 'disabled_reblogs' ) );
	}

	/**
	 * Used for WPCOM ONLY. Comment likes are in their own module in Jetpack.
	 * Returns if comment likes are enabled. Defaults to 'off'
	 *
	 * @return boolean true if we should show comment likes, false if not
	 */
	public function is_comments_enabled() {
		/**
		 * Filters whether Comment Likes are enabled.
		 * true if enabled, false if not.
		 *
		 * @module comment-likes
		 *
		 * @since 2.2.0
		 *
		 * @param bool $option Are Comment Likes enabled sitewide.
		 */
		return (bool) apply_filters( 'jetpack_comment_likes_enabled', get_option( 'jetpack_comment_likes_enabled', false ) );
	}

	/**
	 * Saves the setting in the database.
	 */
	public function admin_settings_callback() {
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'sharing-options' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WordPress core doesn't unslash or verify nonces either.
			return;
		}

		// We're looking for these, and doing a dance to set some stats and save
		// them together in array option.
		if ( ! empty( $_POST['wpl_default'] ) ) {
			$new_state = sanitize_text_field( wp_unslash( $_POST['wpl_default'] ) );
		} else {
			$new_state = 'on';
		}

		if ( ! empty( $_POST['jetpack_reblogs_enabled'] ) ) {
			$reblogs_new_state = sanitize_text_field( wp_unslash( $_POST['jetpack_reblogs_enabled'] ) );
		} else {
			$reblogs_new_state = 'on';
		}

		// Checked (enabled)
		switch ( $new_state ) {
			case 'off':
				update_option( 'disabled_likes', 1 );
				break;
			case 'on':
			default:
				delete_option( 'disabled_likes' );
				break;
		}

		switch ( $reblogs_new_state ) {
			case 'off':
				update_option( 'disabled_reblogs', 1 );
				break;
			case 'on':
			default:
				delete_option( 'disabled_reblogs' );
				break;
		}

		// WPCOM only: Comment Likes
		if ( ! $this->in_jetpack ) {
			if ( ! empty( $_POST['jetpack_comment_likes_enabled'] ) ) {
				$new_comments_state = sanitize_text_field( wp_unslash( $_POST['jetpack_comment_likes_enabled'] ) );
			} else {
				$new_comments_state = false;
			}
			switch ( (bool) $new_comments_state ) {
				case true:
					update_option( 'jetpack_comment_likes_enabled', 1 );
					break;
				case false:
				default:
					update_option( 'jetpack_comment_likes_enabled', 0 );
					break;
			}
		}
	}

	/**
	 * Adds the admin update hook so we can save settings even if Sharedaddy is not enabled.
	 */
	public function process_update_requests_if_sharedaddy_not_loaded() {
		if ( isset( $_GET['page'] ) && ( $_GET['page'] === 'sharing.php' || $_GET['page'] === 'sharing' ) ) {
			if ( isset( $_POST['_wpnonce'] ) && wp_verify_nonce( $_POST['_wpnonce'], 'sharing-options' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- WordPress core doesn't unslash or verify nonces either.
				/** This action is documented in modules/sharedaddy/sharing.php */
				do_action( 'sharing_admin_update' );
				wp_safe_redirect( admin_url( 'options-general.php?page=sharing&update=saved' ) );
				die();
			}
		}
	}

	/**
	 * If sharedaddy is not loaded, we don't have the "Show buttons on" yet, so we need to add that since it affects likes too.
	 */
	public function admin_settings_showbuttonon_init() {
		/** This action is documented in modules/sharedaddy/sharing.php */
		echo apply_filters( 'sharing_show_buttons_on_row_start', '<tr valign="top">' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
		<th scope="row"><label><?php esc_html_e( 'Show buttons on', 'jetpack' ); ?></label></th>
		<td>
			<?php
			$br    = false;
			$shows = array_values( get_post_types( array( 'public' => true ) ) );
			array_unshift( $shows, 'index' );
			$global = $this->get_options();
			foreach ( $shows as $show ) :
				if ( 'index' === $show ) {
					$label = __( 'Front Page, Archive Pages, and Search Results', 'jetpack' );
				} else {
					$post_type_object = get_post_type_object( $show );
					$label            = $post_type_object->labels->name;
				}

				if ( $br ) {
					echo '<br />';
				}
				?>
				<label><input type="checkbox"<?php checked( in_array( $show, $global['show'], true ) ); ?> name="show[]" value="<?php echo esc_attr( $show ); ?>" /> <?php echo esc_html( $label ); ?></label>
				<?php
				$br = true;
				endforeach;
			?>
		</td>
		<?php
		/** This action is documented in modules/sharedaddy/sharing.php */
		echo apply_filters( 'sharing_show_buttons_on_row_end', '</tr>' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * If sharedaddy is not loaded, we still need to save the the settings of the "Show buttons on" option.
	 */
	public function admin_settings_showbuttonon_callback() {
		$options = get_option( 'sharing-options' );
		if ( ! is_array( $options ) ) {
			$options = array();
		}

		$shows   = array_values( get_post_types( array( 'public' => true ) ) );
		$shows[] = 'index';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- triggered due to the 'sharing_admin_update' action, but the code in sharing.php checks for the nonce before firing the action.
		$data = $_POST;

		if ( isset( $data['show'] ) ) {
			if ( is_scalar( $data['show'] ) ) {
				switch ( $data['show'] ) {
					case 'posts':
						$data['show'] = array( 'post', 'page' );
						break;
					case 'index':
						$data['show'] = array( 'index' );
						break;
					case 'posts-index':
						$data['show'] = array( 'post', 'page', 'index' );
						break;
				}
			}

			$data['show'] = array_intersect( $data['show'], $shows );
			if ( $data['show'] ) {
				$options['global']['show'] = $data['show'];
			}
		} else {
			$options['global']['show'] = array();
		}

		update_option( 'sharing-options', $options );
	}
}
