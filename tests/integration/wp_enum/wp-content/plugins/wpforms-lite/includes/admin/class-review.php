<?php

/**
 * Ask for some love.
 *
 * @since 1.3.2
 */
class WPForms_Review {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.3.2
	 */
	public function __construct() {

		// Admin notice requesting review.
		add_action( 'admin_init', [ $this, 'review_request' ] );
		add_action( 'wp_ajax_wpforms_review_dismiss', [ $this, 'review_dismiss' ] );

		// Admin footer text.
		add_filter( 'admin_footer_text', [ $this, 'admin_footer' ], 1, 2 );
		add_action( 'in_admin_footer', [ $this, 'promote_wpforms' ] );
	}

	/**
	 * Add admin notices as needed for reviews.
	 *
	 * @since 1.3.2
	 */
	public function review_request() {

		// Only consider showing the review request to admin users.
		if ( ! is_super_admin() ) {
			return;
		}

		// If the user has opted out of product announcement notifications, don't
		// display the review request.
		if ( wpforms_setting( 'hide-announcements', false ) ) {
			return;
		}

		// Verify that we can do a check for reviews.
		$notices = get_option( 'wpforms_admin_notices', [] );
		$time    = time();
		$load    = false;

		if ( empty( $notices['review_request'] ) ) {
			$notices['review_request'] = [
				'time'      => $time,
				'dismissed' => false,
			];

			update_option( 'wpforms_admin_notices', $notices );

			return;
		}

		// Check if it has been dismissed or not.
		if (
			( isset( $notices['review_request']['dismissed'] ) &&
			! $notices['review_request']['dismissed'] ) &&
			(
				isset( $notices['review_request']['time'] ) &&
				( ( $notices['review_request']['time'] + DAY_IN_SECONDS ) <= $time )
			)
		) {
			$load = true;
		}

		// If we cannot load, return early.
		if ( ! $load ) {
			return;
		}

		// Logic is slightly different depending on what's at our disposal.
		if ( wpforms()->is_pro() && class_exists( 'WPForms_Entry_Handler', false ) ) {
			$this->review();
		} else {
			$this->review_lite();
		}
	}

	/**
	 * Maybe show review request.
	 *
	 * @since 1.3.9
	 */
	public function review() {

		// Fetch total entries.
		$entries = wpforms()->entry->get_entries( [ 'number' => 50 ], true );

		// Only show review request if the site has collected at least 50 entries.
		if ( empty( $entries ) || $entries < 50 ) {
			return;
		}

		ob_start();

		// We have a candidate! Output a review message.
		?>
		<p><?php esc_html_e( 'Hey, I noticed you collected over 50 entries from WPForms - that’s awesome! Could you please do me a BIG favor and give it a 5-star rating on WordPress to help us spread the word and boost our motivation?', 'wpforms-lite' ); ?></p>
		<p><strong><?php echo wp_kses( __( '~ Syed Balkhi<br>Co-Founder of WPForms', 'wpforms-lite' ), [ 'br' => [] ] ); ?></strong></p>
		<p>
			<a href="https://wordpress.org/support/plugin/wpforms-lite/reviews/?filter=5#new-post" class="wpforms-notice-dismiss wpforms-review-out" target="_blank" rel="noopener"><?php esc_html_e( 'Ok, you deserve it', 'wpforms-lite' ); ?></a><br>
			<a href="#" class="wpforms-notice-dismiss" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Nope, maybe later', 'wpforms-lite' ); ?></a><br>
			<a href="#" class="wpforms-notice-dismiss" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'I already did', 'wpforms-lite' ); ?></a>
		</p>
		<?php

		\WPForms\Admin\Notice::info(
			ob_get_clean(),
			[
				'dismiss' => \WPForms\Admin\Notice::DISMISS_GLOBAL,
				'slug'    => 'review_request',
				'autop'   => false,
				'class'   => 'wpforms-review-notice',
			]
		);
	}

	/**
	 * Maybe show Lite review request.
	 *
	 * @since 1.3.9
	 */
	public function review_lite() {

		// Fetch when plugin was initially installed.
		$activated = get_option( 'wpforms_activated', [] );

		if ( ! empty( $activated['lite'] ) ) {
			// Only continue if plugin has been installed for at least 14 days.
			if ( ( $activated['lite'] + ( DAY_IN_SECONDS * 14 ) ) > time() ) {
				return;
			}
		} else {
			$activated['lite'] = time();

			update_option( 'wpforms_activated', $activated );

			return;
		}

		// Only proceed with displaying if the user created at least one form.
		$form_count = wp_count_posts( 'wpforms' );

		if ( empty( $form_count->publish ) ) {
			return;
		}

		// Check if the Constant Contact notice is displaying.
		$cc = get_option( 'wpforms_constant_contact', false );

		// If it's displaying don't ask for review until they configure CC or
		// dismiss the notice.
		if ( $cc ) {
			return;
		}

		ob_start();

		// We have a candidate! Output a review message.
		?>
		<p><?php esc_html_e( 'Hey, I noticed you created a contact form with WPForms - that’s awesome! Could you please do me a BIG favor and give it a 5-star rating on WordPress to help us spread the word and boost our motivation?', 'wpforms-lite' ); ?></p>
		<p><strong><?php echo wp_kses( __( '~ Syed Balkhi<br>Co-Founder of WPForms', 'wpforms-lite' ), [ 'br' => [] ] ); ?></strong></p>
		<p>
			<a href="https://wordpress.org/support/plugin/wpforms-lite/reviews/?filter=5#new-post" class="wpforms-notice-dismiss wpforms-review-out" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Ok, you deserve it', 'wpforms-lite' ); ?></a><br>
			<a href="#" class="wpforms-notice-dismiss" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Nope, maybe later', 'wpforms-lite' ); ?></a><br>
			<a href="#" class="wpforms-notice-dismiss" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'I already did', 'wpforms-lite' ); ?></a>
		</p>
		<?php

		\WPForms\Admin\Notice::info(
			ob_get_clean(),
			[
				'dismiss' => \WPForms\Admin\Notice::DISMISS_GLOBAL,
				'slug'    => 'review_lite_request',
				'autop'   => false,
				'class'   => 'wpforms-review-notice',
			]
		);
	}

	/**
	 * Dismiss the review admin notice.
	 *
	 * @deprecated 1.6.7.1
	 *
	 * @since 1.3.2
	 */
	public function review_dismiss() {

		_deprecated_function( __METHOD__, '1.6.7.1 of the WPForms plugin' );

		$review              = get_option( 'wpforms_review', [] );
		$review['time']      = time();
		$review['dismissed'] = true;

		update_option( 'wpforms_review', $review );

		die;
	}

	/**
	 * When user is on a WPForms related admin page, display footer text
	 * that graciously asks them to rate us.
	 *
	 * @since 1.3.2
	 *
	 * @param string $text Footer text.
	 *
	 * @return string
	 */
	public function admin_footer( $text ) {

		global $current_screen;

		if ( ! empty( $current_screen->id ) && strpos( $current_screen->id, 'wpforms' ) !== false ) {
			$url  = 'https://wordpress.org/support/plugin/wpforms-lite/reviews/?filter=5#new-post';
			$text = sprintf(
				wp_kses( /* translators: $1$s - WPForms plugin name; $2$s - WP.org review link; $3$s - WP.org review link. */
					__( 'Please rate %1$s <a href="%2$s" target="_blank" rel="noopener noreferrer">&#9733;&#9733;&#9733;&#9733;&#9733;</a> on <a href="%3$s" target="_blank" rel="noopener">WordPress.org</a> to help us spread the word.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				'<strong>WPForms</strong>',
				$url,
				$url
			);
		}

		return $text;
	}

	/**
	 * Pre-footer promotion block, displayed on all WPForms admin pages except Form Builder.
	 *
	 * @since 1.8.0
	 */
	public function promote_wpforms() {

		// Some 3rd-party addons may use page slugs that start with `wpforms-` (e.g. WPForms Views),
		// so we should define exact pages we want the footer to be displayed on instead
		// of targeting any page that looks like a WPForms page.
		$plugin_pages = [
			'wpforms-about',
			'wpforms-addons',
			'wpforms-analytics',
			'wpforms-community',
			'wpforms-entries',
			'wpforms-overview',
			'wpforms-settings',
			'wpforms-smtp',
			'wpforms-templates',
			'wpforms-tools',
		];

		// phpcs:ignore WordPress.Security.NonceVerification
		$current_page = isset( $_REQUEST['page'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['page'] ) ) : '';

		if ( ! in_array( $current_page, $plugin_pages, true ) ) {
			return;
		}

		$links = [
			[
				'url'    => wpforms()->is_pro() ?
					wpforms_utm_link(
						'https://wpforms.com/account/support/',
						'Plugin Footer',
						'Contact Support'
					) : 'https://wordpress.org/support/plugin/wpforms-lite/',
				'text'   => __( 'Support', 'wpforms-lite' ),
				'target' => '_blank',
			],
			[
				'url'    => wpforms_utm_link(
					'https://wpforms.com/docs/',
					'Plugin Footer',
					'Plugin Documentation'
				),
				'text'   => __( 'Docs', 'wpforms-lite' ),
				'target' => '_blank',
			],
			[
				'url'    => 'https://www.facebook.com/groups/461389447755778',
				'text'   => __( 'VIP Circle', 'wpforms-lite' ),
				'target' => '_blank',
			],
			[
				'url'  => admin_url( 'admin.php?page=wpforms-about' ),
				'text' => __( 'Free Plugins', 'wpforms-lite' ),
			],
		];

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin/promotion',
			[
				'title' => __( 'Made with ♥ by the WPForms Team', 'wpforms-lite' ),
				'links' => $links,
			],
			true
		);
	}
}

new WPForms_Review();
