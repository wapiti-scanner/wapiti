<?php

/**
 * Primary overview page inside the admin which lists all forms.
 *
 * @since 1.0.0
 */
class WPForms_Overview {

	/**
	 * Overview Table instance.
	 *
	 * @since 1.7.2
	 *
	 * @var WPForms_Overview_Table
	 */
	private $overview_table;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		// Maybe load overview page.
		add_action( 'admin_init', [ $this, 'init' ] );

		// Setup screen options. Needs to be here as admin_init hook it too late.
		add_action( 'load-toplevel_page_wpforms-overview', [ $this, 'screen_options' ] );
		add_filter( 'set-screen-option', [ $this, 'screen_options_set' ], 10, 3 );
		add_filter( 'set_screen_option_wpforms_forms_per_page', [ $this, 'screen_options_set' ], 10, 3 );
	}

	/**
	 * Determine if the user is viewing the overview page, if so, party on.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Only load if we are actually on the overview page.
		if ( ! wpforms_is_admin_page( 'overview' ) ) {
			return;
		}

		// Avoid recursively include _wp_http_referer in the REQUEST_URI.
		$this->remove_referer();

		add_action( 'current_screen', [ $this, 'init_overview_table' ] );

		// The overview page leverages WP_List_Table so we must load it.
		if ( ! class_exists( 'WP_List_Table', false ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
		}

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_action( 'wpforms_admin_page', [ $this, 'output' ] );

		// Provide hook for addons.
		do_action( 'wpforms_overview_init' );
	}

	/**
	 * Init overview table class.
	 *
	 * @since 1.7.2
	 */
	public function init_overview_table() {

		// Load the class that builds the overview table.
		require_once WPFORMS_PLUGIN_DIR . 'includes/admin/overview/class-overview-table.php';

		$this->overview_table = WPForms_Overview_Table::get_instance();
	}

	/**
	 * Remove previous `_wp_http_referer` variable from the REQUEST_URI.
	 *
	 * @since 1.7.2
	 */
	private function remove_referer() {

		if ( isset( $_SERVER['REQUEST_URI'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$_SERVER['REQUEST_URI'] = remove_query_arg( '_wp_http_referer', wp_unslash( $_SERVER['REQUEST_URI'] ) );
		}
	}

	/**
	 * Add per-page screen option to the Forms table.
	 *
	 * @since 1.0.0
	 */
	public function screen_options() {

		$screen = get_current_screen();

		if ( $screen === null || $screen->id !== 'toplevel_page_wpforms-overview' ) {
			return;
		}

		add_screen_option(
			'per_page',
			[
				'label'   => esc_html__( 'Number of forms per page:', 'wpforms-lite' ),
				'option'  => 'wpforms_forms_per_page',
				'default' => apply_filters( 'wpforms_overview_per_page', 20 ),
			]
		);
	}

	/**
	 * Form table per-page screen option value.
	 *
	 * @since 1.0.0
	 *
	 * @param bool   $keep   Whether to save or skip saving the screen option value. Default false.
	 * @param string $option The option name.
	 * @param int    $value  The number of rows to use.
	 *
	 * @return mixed
	 */
	public function screen_options_set( $keep, $option, $value ) {

		if ( $option === 'wpforms_forms_per_page' ) {
			return $value;
		}

		return $keep;
	}

	/**
	 * Enqueue assets for the overview page.
	 *
	 * @since 1.0.0
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-admin-forms-overview',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/forms/overview{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		// Hook for addons.
		do_action( 'wpforms_overview_enqueue' );
	}

	/**
	 * Determine if it is an empty state.
	 *
	 * @since 1.7.5
	 */
	private function is_empty_state() {

		// phpcs:disable WordPress.Security.NonceVerification.Recommended

		return empty( $this->overview_table->items ) &&
			! isset( $_GET['search']['term'] ) &&
			! isset( $_GET['status'] ) &&
			! isset( $_GET['tags'] ) &&
			array_sum( wpforms()->get( 'forms_views' )->get_count() ) === 0;

		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Build the output for the overview page.
	 *
	 * @since 1.0.0
	 */
	public function output() {

		?>
		<div id="wpforms-overview" class="wrap wpforms-admin-wrap">

			<h1 class="page-title">
				<?php esc_html_e( 'Forms Overview', 'wpforms-lite' ); ?>
				<?php if ( wpforms_current_user_can( 'create_forms' ) ) : ?>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-builder&view=setup' ) ); ?>" class="add-new-h2 wpforms-btn-orange">
						<?php esc_html_e( 'Add New', 'wpforms-lite' ); ?>
					</a>
				<?php endif; ?>
			</h1>

			<div class="wpforms-admin-content">

				<?php
				$this->overview_table->prepare_items();

				// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
				/**
				 * Fires before forms overview list table output.
				 *
				 * @since 1.6.0.1
				 */
				do_action( 'wpforms_admin_overview_before_table' );
				// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

				if ( $this->is_empty_state() ) {

					// Output no forms screen.
					echo wpforms_render( 'admin/empty-states/no-forms' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

				} else {
				?>
					<form id="wpforms-overview-table" method="get" action="<?php echo esc_url( admin_url( 'admin.php?page=wpforms-overview' ) ); ?>">

						<input type="hidden" name="post_type" value="wpforms" />
						<input type="hidden" name="page" value="wpforms-overview" />

						<?php
							$this->overview_table->search_box( esc_html__( 'Search Forms', 'wpforms-lite' ), 'wpforms-overview-search' );
							$this->overview_table->views();
							$this->overview_table->display();
						?>

					</form>
				<?php } ?>

			</div>

		</div>
		<?php
	}

	/**
	 * Admin notices.
	 *
	 * @since 1.5.7
	 * @deprecated 1.7.3
	 */
	public function notices() {

		_deprecated_function( __METHOD__, '1.7.3 of the WPForms', "wpforms()->get( 'forms_bulk_actions' )->notices()" );

		wpforms()->get( 'forms_bulk_actions' )->notices();
	}

	/**
	 * Process the bulk table actions.
	 *
	 * @since 1.5.7
	 * @deprecated 1.7.3
	 */
	public function process_bulk_actions() {

		_deprecated_function( __METHOD__, '1.7.3 of the WPForms', "wpforms()->get( 'forms_bulk_actions' )->process()" );

		wpforms()->get( 'forms_bulk_actions' )->process();
	}

	/**
	 * Remove certain arguments from a query string that WordPress should always hide for users.
	 *
	 * @since 1.5.7
	 * @deprecated 1.7.3
	 *
	 * @param array $removable_query_args An array of parameters to remove from the URL.
	 *
	 * @return array Extended/filtered array of parameters to remove from the URL.
	 */
	public function removable_query_args( $removable_query_args ) {

		_deprecated_function( __METHOD__, '1.7.3 of the WPForms', "wpforms()->get( 'forms_bulk_actions' )->removable_query_args()" );

		return wpforms()->get( 'forms_bulk_actions' )->removable_query_args( $removable_query_args );
	}
}

new WPForms_Overview();
