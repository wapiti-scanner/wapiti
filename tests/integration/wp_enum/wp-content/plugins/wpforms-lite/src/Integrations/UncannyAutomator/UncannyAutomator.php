<?php

namespace WPForms\Integrations\UncannyAutomator;

use WPForms\Integrations\IntegrationInterface;

/**
 * UncannyAutomator class.
 *
 * @since 1.7.0
 */
class UncannyAutomator implements IntegrationInterface {

	/**
	 * Custom priority for a provider, that will affect loading/placement order.
	 *
	 * @since 1.7.0
	 *
	 * @var int
	 */
	const PRIORITY = 15;

	/**
	 * Unique provider slug.
	 *
	 * @since 1.7.0
	 *
	 * @var string
	 */
	const SLUG = 'uncanny-automator';

	/**
	 * Translatable provider name.
	 *
	 * @since 1.7.0
	 *
	 * @var string
	 */
	private $name;

	/**
	 * Custom provider icon (logo).
	 *
	 * @since 1.7.0
	 *
	 * @var string
	 */
	private $icon;

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.7.0
	 *
	 * @return bool
	 */
	public function allow_load() {

		global $wp_version;

		return PHP_VERSION_ID >= 50600 && version_compare( $wp_version, '5.3', '>=' ) && ! function_exists( 'Automator' );
	}

	/**
	 * Load the integration.
	 *
	 * @since 1.7.0
	 */
	public function load() {

		$this->name = esc_html__( 'Uncanny Automator', 'wpforms-lite' );
		$this->icon = WPFORMS_PLUGIN_URL . 'assets/images/icon-provider-uncanny-automator.png';

		$this->hooks();
	}

	/**
	 * Register all hooks.
	 *
	 * @since 1.7.0
	 */
	private function hooks() {

		add_action( 'wpforms_providers_panel_sidebar', [ $this, 'display_sidebar' ], self::PRIORITY );
		add_action( 'wpforms_providers_panel_content', [ $this, 'display_content' ], self::PRIORITY );

		add_filter( 'automator_on_activate_redirect_to_dashboard', '__return_false' );
		add_action( 'wpforms_plugin_activated', [ $this, 'update_source' ] );
	}

	/**
	 * Display content inside the panel sidebar area.
	 *
	 * @since 1.7.0
	 */
	public function display_sidebar() {

		printf(
			'<a href="#" class="wpforms-panel-sidebar-section icon wpforms-panel-sidebar-section-%1$s" data-section="%1$s">
				<img src="%2$s" alt="%4$s">%3$s<i class="fa fa-angle-right wpforms-toggle-arrow"></i>
			</a>',
			esc_attr( self::SLUG ),
			esc_url( $this->icon ),
			esc_html( $this->name ),
			esc_attr( $this->name )
		);
	}

	/**
	 * Display content inside the panel area.
	 *
	 * @since 1.7.0
	 */
	public function display_content() {

		$plugins        = get_plugins();
		$is_installed   = ! empty( $plugins[ sprintf( '%1$s/%1$s.php', self::SLUG ) ] );
		$button_label   = $is_installed ? esc_html__( 'Activate Now', 'wpforms-lite' ) : esc_html__( 'Install Now', 'wpforms-lite' );
		$learn_more_url = esc_url(
			add_query_arg(
				[
					'utm_source'  => 'wpforms',
					'utm_medium'  => 'form_marketing',
					'utm_content' => 'learn_more_btn_before_install',
					'utm_r'       => 150,
				],
				'https://automatorplugin.com/wpforms-automation/'
			)
		);
		?>

		<div
				class="wpforms-panel-content-section wpforms-builder-provider wpforms-panel-content-section-<?php echo esc_attr( self::SLUG ); ?>"
				id="<?php echo esc_attr( self::SLUG ); ?>-provider"
				data-provider="<?php echo esc_attr( self::SLUG ); ?>">

			<div class="wpforms-builder-provider-title wpforms-panel-content-section-title">
				<?php echo esc_html( $this->name ); ?>
				<?php
				printf(
					'<button class="wpforms-builder-provider-title-add education-modal"
					data-name="%1$s"
					data-slug="%2$s"
					data-action="%3$s"
					data-path="%2$s/%2$s.php"
					data-type="plugin"
					data-url="https://downloads.wordpress.org/plugin/%2$s.zip"
					data-nonce="%4$s"
					data-hide-on-success="true">%5$s</button>',
					esc_attr(
						sprintf( /* translators: %s - plugin name. */
							__( '%s plugin', 'wpforms-lite' ),
							$this->name
						)
					),
					esc_attr( self::SLUG ),
					$is_installed ? 'activate' : 'install',
					esc_attr( wp_create_nonce( 'wpforms-admin' ) ),
					esc_html( $button_label )
				);
				?>
			</div>

			<div class="wpforms-builder-provider-connections-default">
				<img src="<?php echo esc_url( $this->icon ); ?>" alt="<?php echo esc_attr( $this->name ); ?>">
				<div class="wpforms-builder-provider-settings-default-content">
					<h2><?php esc_html_e( 'Put Your WordPress Site on Autopilot', 'wpforms-lite' ); ?></h2>
					<p><?php esc_html_e( 'Build powerful automations that control what happens on form submission. Connect your forms to Google Sheets, Zoom, social media, membership plugins, elearning platforms, and more with Uncanny Automator.', 'wpforms-lite' ); ?></p>
					<p>
						<a href="<?php echo esc_url( $learn_more_url ); ?>"
						   class="wpforms-btn wpforms-btn-md wpforms-btn-orange"
						   target="_blank"
						   rel="noopener noreferrer">
							<?php esc_html_e( 'Learn More', 'wpforms-lite' ); ?>
						</a>
					</p>
				</div>
			</div>

			<div class="wpforms-builder-provider-body">
				<div class="wpforms-provider-connections-wrap wpforms-clear">
					<div class="wpforms-builder-provider-connections"></div>
				</div>
			</div>

		</div>

		<?php
	}

	/**
	 * Update source.
	 *
	 * @since 1.7.0
	 *
	 * @param string $plugin_base Path to the plugin file relative to the plugins' directory.
	 */
	public function update_source( $plugin_base ) {

		if ( sprintf( '%1$s/%1$s.php', self::SLUG ) !== $plugin_base ) {
			return;
		}

		update_option( 'uncannyautomator_source', 'wpforms' );
	}
}
