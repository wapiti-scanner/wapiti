<?php

namespace WPForms\Admin\Tools;

/**
 * Main Tools class.
 *
 * @since 1.6.6
 */
class Tools {

	/**
	 * Tools page slug.
	 *
	 * @since 1.6.6
	 */
	const SLUG = 'wpforms-tools';

	/**
	 * Available pages.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	private $views = [];

	/**
	 * The current view.
	 *
	 * @since 1.6.6
	 *
	 * @var null|\WPForms\Admin\Tools\Views\View
	 */
	private $view;

	/**
	 * The active view slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	private $active_view_slug;

	/**
	 * Initialize class.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		if ( ! $this->is_tools_page() ) {
			return;
		}

		$this->init_view();
		$this->hooks();
	}

	/**
	 * Check if we're on tools page.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	private function is_tools_page() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : '';

		// Only load if we are actually on the settings page.
		return $page === self::SLUG;
	}

	/**
	 * Init current view.
	 *
	 * @since 1.6.6
	 */
	private function init_view() {

		$view_ids = array_keys( $this->get_views() );

		// Determine the current active settings tab.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$this->active_view_slug = ! empty( $_GET['view'] ) ? sanitize_key( $_GET['view'] ) : 'import';

		// If the user tries to load an invalid view - fallback to the first available.
		if (
			! in_array( $this->active_view_slug, $view_ids, true ) &&
			! has_action( 'wpforms_tools_display_tab_' . $this->active_view_slug )
		) {
			$this->active_view_slug = reset( $view_ids );
		}

		if ( isset( $this->views[ $this->active_view_slug ] ) ) {
			$this->view = $this->views[ $this->active_view_slug ];

			$this->view->init();
		}
	}

	/**
	 * Get Views.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	public function get_views() {

		if ( empty( $this->views ) ) {
			$this->views = [
				'import'           => new Views\Import(),
				'importer'         => new Views\Importer(),
				'export'           => new Views\Export(),
				'system'           => new Views\System(),
				'action-scheduler' => new Views\ActionScheduler(),
				'logs'             => new Views\Logs(),
			];
		}

		$this->views = apply_filters( 'wpforms_tools_views', $this->views );

		return array_filter(
			$this->views,
			static function ( $view ) {

				return $view->check_capability();
			}
		);
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_admin_page', [ $this, 'output' ] );

		// Hook for addons.
		do_action( 'wpforms_tools_init' );
	}

	/**
	 * Build the output for the Tools admin page.
	 *
	 * @since 1.6.6
	 */
	public function output() {
		?>
		<div id="wpforms-tools" class="wrap wpforms-admin-wrap wpforms-tools-tab-<?php echo esc_attr( $this->active_view_slug ); ?>">

			<?php
			if ( $this->view && $this->view->show_nav() ) {

				echo '<ul class="wpforms-admin-tabs">';
				foreach ( $this->views as $slug => $view ) {
					if ( $view->hide_from_nav() || ! $view->check_capability() ) {
						continue;
					}

					echo '<li>';
					printf(
						'<a href="%1$s" class="%2$s">%3$s</a>',
						esc_url( $view->get_link() ),
						sanitize_html_class( $this->active_view_slug === $slug ? 'active' : '' ),
						esc_html( $view->get_label() )
					);
					echo '</li>';
				}
				echo '</ul>';
			}
			?>

			<h1 class="wpforms-h1-placeholder"></h1>

			<div class="wpforms-admin-content wpforms-admin-settings">
				<?php
				if ( $this->view ) {
					$this->view->display();
				} else {
					do_action( 'wpforms_tools_display_tab_' . $this->active_view_slug );
				}
				?>
			</div>
		</div>
		<?php
	}
}
