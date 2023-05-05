<?php

/**
 * Welcome page class.
 *
 * This page is shown when the plugin is activated.
 *
 * @since 1.0.0
 */
class WPForms_Welcome {

	/**
	 * Hidden welcome page slug.
	 *
	 * @since 1.5.6
	 */
	const SLUG = 'wpforms-getting-started';

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		add_action( 'plugins_loaded', [ $this, 'hooks' ] );
	}

	/**
	 * Register all WP hooks.
	 *
	 * @since 1.5.6
	 */
	public function hooks() {

		// If user is in admin ajax or doing cron, return.
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		// If user cannot manage_options, return.
		if ( ! wpforms_current_user_can() ) {
			return;
		}

		add_action( 'admin_menu', [ $this, 'register' ] );
		add_action( 'admin_head', [ $this, 'hide_menu' ] );
		add_action( 'admin_init', [ $this, 'redirect' ], 9999 );
	}

	/**
	 * Register the pages to be used for the Welcome screen (and tabs).
	 *
	 * These pages will be removed from the Dashboard menu, so they will
	 * not actually show. Sneaky, sneaky.
	 *
	 * @since 1.0.0
	 */
	public function register() {

		// Getting started - shows after installation.
		add_dashboard_page(
			esc_html__( 'Welcome to WPForms', 'wpforms-lite' ),
			esc_html__( 'Welcome to WPForms', 'wpforms-lite' ),
			apply_filters( 'wpforms_welcome_cap', wpforms_get_capability_manage_options() ),
			self::SLUG,
			[ $this, 'output' ]
		);
	}

	/**
	 * Removed the dashboard pages from the admin menu.
	 *
	 * This means the pages are still available to us, but hidden.
	 *
	 * @since 1.0.0
	 */
	public function hide_menu() {

		remove_submenu_page( 'index.php', self::SLUG );
	}

	/**
	 * Welcome screen redirect.
	 *
	 * This function checks if a new install or update has just occurred. If so,
	 * then we redirect the user to the appropriate page.
	 *
	 * @since 1.0.0
	 */
	public function redirect() {

		// Check if we should consider redirection.
		if ( ! get_transient( 'wpforms_activation_redirect' ) ) {
			return;
		}

		// If we are redirecting, clear the transient so it only happens once.
		delete_transient( 'wpforms_activation_redirect' );

		// Check option to disable welcome redirect.
		if ( get_option( 'wpforms_activation_redirect', false ) ) {
			return;
		}

		// Only do this for single site installs.
		if ( isset( $_GET['activate-multi'] ) || is_network_admin() ) { // WPCS: CSRF ok.
			return;
		}

		// Check if this is an update or first install.
		$upgrade = get_option( 'wpforms_version_upgraded_from' );

		if ( ! $upgrade ) {
			// Initial install.
			wp_safe_redirect( admin_url( 'index.php?page=' . self::SLUG ) );
			exit;
		}
	}

	/**
	 * Getting Started screen. Shows after first install.
	 *
	 * @since 1.0.0
	 */
	public function output() {

		$class = wpforms()->is_pro() ? 'pro' : 'lite';
		?>

		<div id="wpforms-welcome" class="<?php echo sanitize_html_class( $class ); ?>">

			<div class="container">

				<div class="intro">

					<div class="sullie">
						<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/sullie.png" alt="<?php esc_attr_e( 'Sullie the WPForms mascot', 'wpforms-lite' ); ?>">
					</div>

					<div class="block">
						<h1><?php esc_html_e( 'Welcome to WPForms', 'wpforms-lite' ); ?></h1>
						<h6><?php esc_html_e( 'Thank you for choosing WPForms - the most powerful drag & drop WordPress form builder in the market.', 'wpforms-lite' ); ?></h6>
					</div>

					<a href="#" class="play-video" title="<?php esc_attr_e( 'Watch how to create your first form', 'wpforms-lite' ); ?>">
						<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-video.png" alt="<?php esc_attr_e( 'Watch how to create your first form', 'wpforms-lite' ); ?>" class="video-thumbnail">
					</a>

					<div class="block">

						<h6><?php esc_html_e( 'WPForms makes it easy to create forms in WordPress. You can watch the video tutorial or read our guide on how create your first form.', 'wpforms-lite' ); ?></h6>

						<div class="button-wrap wpforms-clear">
							<div class="left">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder' ) ); ?>" class="wpforms-btn wpforms-btn-block wpforms-btn-lg wpforms-btn-orange">
									<?php esc_html_e( 'Create Your First Form', 'wpforms-lite' ); ?>
								</a>
							</div>
							<div class="right">
								<a href="<?php echo esc_url( wpforms_utm_link( 'https://wpforms.com/docs/creating-first-form/', 'welcome-page', 'Read the Full Guide' ) ); ?>"
									class="wpforms-btn wpforms-btn-block wpforms-btn-lg wpforms-btn-grey" target="_blank" rel="noopener noreferrer">
									<?php esc_html_e( 'Read the Full Guide', 'wpforms-lite' ); ?>
								</a>
							</div>
						</div>

					</div>

				</div><!-- /.intro -->

				<?php do_action( 'wpforms_welcome_intro_after' ); ?>

				<div class="features">

					<div class="block">

						<h1><?php esc_html_e( 'WPForms Features &amp; Addons', 'wpforms-lite' ); ?></h1>
						<h6><?php esc_html_e( 'WPForms is both easy to use and extremely powerful. We have tons of helpful features that allow us to give you everything you need from a form builder.', 'wpforms-lite' ); ?></h6>

						<div class="feature-list wpforms-clear">

							<div class="feature-block first">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-1.png">
								<h5><?php esc_html_e( 'Drag &amp; Drop Form Builder', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Easily create an amazing form in just a few minutes without writing any code.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block last">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-2.png">
								<h5><?php esc_html_e( 'Form Templates', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Start with pre-built form templates to save even more time.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block first">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-3.png">
								<h5><?php esc_html_e( 'Responsive Mobile Friendly', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'WPForms is 100% responsive meaning it works on mobile, tablets & desktop.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block last">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-4.png">
								<h5><?php esc_html_e( 'Smart Conditional Logic', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Easily create high performance forms with our smart conditional logic.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block first">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-5.png">
								<h5><?php esc_html_e( 'Instant Notifications', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Respond to leads quickly with our instant form notification feature for your team.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block last">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-6.png">
								<h5><?php esc_html_e( 'Entry Management', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'View all your leads in one place to streamline your workflow.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block first">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-7.png">
								<h5><?php esc_html_e( 'Payments Made Easy', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Easily collect payments, donations, and online orders without hiring a developer.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block last">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-8.png">
								<h5><?php esc_html_e( 'Marketing &amp; Subscriptions', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Create subscription forms and connect with your email marketing service.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block first">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-9.png">
								<h5><?php esc_html_e( 'Easy to Embed', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Easily embed your forms in blog posts, pages, sidebar widgets, footer, etc.', 'wpforms-lite' ); ?></p>
							</div>

							<div class="feature-block last">
								<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-feature-icon-10.png">
								<h5><?php esc_html_e( 'Spam Protection', 'wpforms-lite' ); ?></h5>
								<p><?php esc_html_e( 'Our smart captcha and spam protection automatically prevents spam submissions.', 'wpforms-lite' ); ?></p>
							</div>

						</div>

						<div class="button-wrap">
							<a href="<?php echo esc_url( wpforms_utm_link( 'https://wpforms.com/features/', 'welcome-page', 'See All Features' ) ); ?>"
								class="wpforms-btn wpforms-btn-lg wpforms-btn-grey" rel="noopener noreferrer" target="_blank">
								<?php esc_html_e( 'See All Features', 'wpforms-lite' ); ?>
							</a>
						</div>

					</div>

				</div><!-- /.features -->

				<div class="upgrade-cta upgrade">

					<div class="block wpforms-clear">

						<div class="left">
							<h2><?php esc_html_e( 'Upgrade to PRO', 'wpforms-lite' ); ?></h2>
							<ul>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Advanced Fields', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Conditional Logic', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Payment Forms', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Surveys & Polls', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Signatures', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Form Abandonment', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Entry Management', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'File Uploads', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Geolocation', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Conversational Forms', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'User Registration', 'wpforms-lite' ); ?></li>
								<li><span class="dashicons dashicons-yes"></span> <?php esc_html_e( 'Marketing Integrations', 'wpforms-lite' ); ?></li>
							</ul>
						</div>

						<div class="right">
							<h2><span><?php esc_html_e( 'PRO', 'wpforms-lite' ); ?></span></h2>
							<div class="price">
								<span class="amount">199</span><br>
								<span class="term"><?php esc_html_e( 'per year', 'wpforms-lite' ); ?></span>
							</div>
							<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'welcome', 'Upgrade Now CTA Section' ) ); ?>" rel="noopener noreferrer" target="_blank"
								class="wpforms-btn wpforms-btn-block wpforms-btn-lg wpforms-btn-orange wpforms-upgrade-modal">
								<?php esc_html_e( 'Upgrade Now', 'wpforms-lite' ); ?>
							</a>
						</div>

					</div>

				</div>

				<div class="testimonials upgrade">

					<div class="block">

						<h1><?php esc_html_e( 'Testimonials', 'wpforms-lite' ); ?></h1>

						<div class="testimonial-block wpforms-clear">
							<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-testimonial-bill.jpg">
							<p><?php esc_html_e( 'WPForms is by far the easiest form plugin to use. My clients love it – it’s one of the few plugins they can use without any training. As a developer I appreciate how fast, modern, clean and extensible it is.', 'wpforms-lite' ); ?>
							<p>
							<p><strong>Bill Erickson</strong>, Erickson Web Consulting</p>
						</div>

						<div class="testimonial-block wpforms-clear">
							<img src="<?php echo WPFORMS_PLUGIN_URL; ?>assets/images/welcome-testimonial-david.jpg">
							<p><?php esc_html_e( 'As a business owner, time is my most valuable asset. WPForms allow me to create smart online forms with just a few clicks. With their pre-built form templates and the drag & drop builder, I can create a new form that works in less than 2 minutes without writing a single line of code. Well worth the investment.', 'wpforms-lite' ); ?>
							<p>
							<p><strong>David Henzel</strong>, MaxCDN</p>
						</div>

					</div>

				</div><!-- /.testimonials -->

				<div class="footer">

					<div class="block wpforms-clear">

						<div class="button-wrap wpforms-clear">
							<div class="left">
								<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder' ) ); ?>"
									class="wpforms-btn wpforms-btn-block wpforms-btn-lg wpforms-btn-orange">
									<?php esc_html_e( 'Create Your First Form', 'wpforms-lite' ); ?>
								</a>
							</div>
							<div class="right">
								<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'welcome', 'Upgrade to WPForms Pro' ) ); ?>" target="_blank" rel="noopener noreferrer"
									class="wpforms-btn wpforms-btn-block wpforms-btn-lg wpforms-btn-trans-green wpforms-upgrade-modal">
									<span class="underline">
										<?php esc_html_e( 'Upgrade to WPForms Pro', 'wpforms-lite' ); ?> <span class="dashicons dashicons-arrow-right"></span>
									</span>
								</a>
							</div>
						</div>

					</div>

				</div><!-- /.footer -->

			</div><!-- /.container -->

		</div><!-- /#wpforms-welcome -->
		<?php
	}
}

new WPForms_Welcome();
