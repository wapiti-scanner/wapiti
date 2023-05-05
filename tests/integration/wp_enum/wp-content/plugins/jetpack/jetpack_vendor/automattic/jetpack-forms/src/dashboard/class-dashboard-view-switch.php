<?php
/**
 * Jetpack forms dashboard view switch.
 *
 * @package automattic/jetpack-forms
 */

namespace Automattic\Jetpack\Forms\Dashboard;

use Automattic\Jetpack\Forms\Jetpack_Forms;
use JETPACK__VERSION;

/**
 * Understands switching between classic and redesigned versions of the feedback admin area.
 */
class Dashboard_View_Switch {

	/**
	 * Identifier denoting that the classic WP Admin view should be used.
	 *
	 * @var string
	 */
	const CLASSIC_VIEW = 'classic';

	/**
	 * Identifier denoting that the modern view version should be used.
	 *
	 * @var string
	 */
	const MODERN_VIEW = 'modern';

	/**
	 * Initialize the switch.
	 */
	public function init() {
		add_action( 'admin_print_styles', array( $this, 'print_styles' ) );
		add_filter( 'in_admin_header', array( $this, 'render_switch' ) );
		add_action( 'admin_footer', array( $this, 'add_scripts' ) );
		add_action( 'current_screen', array( $this, 'handle_preferred_view' ) );
	}

	/**
	 * Render the switch.
	 */
	public function render_switch() {
		if ( ! $this->is_visible() ) {
			return;
		}

		?>
		<div id="jetpack-forms__view-link-wrap" class="hide-if-no-js screen-meta-toggle">
			<button type="button" id="jetpack-forms__view-link" class="button show-settings" aria-expanded="false"><?php echo esc_html_x( 'View', 'View options to switch between', 'jetpack-forms' ); ?></button>
		</div>
		<div id="jetpack-forms__view-wrap" class="screen-options-tab__wrapper hide-if-no-js hidden" tabindex="-1">
			<div class="screen-options-tab__dropdown" data-testid="screen-options-dropdown">
				<div class="jp-forms__view-switcher">
					<a class="jp-forms__view-switcher-button <?php echo $this->is_classic_view() ? 'is-active' : ''; ?>" href="<?php echo esc_url( add_query_arg( 'preferred-view', self::CLASSIC_VIEW, 'edit.php?post_type=feedback' ) ); ?>">
						<strong><?php esc_html_e( 'Classic', 'jetpack-forms' ); ?></strong>
						<?php esc_html_e( 'The classic WP-Admin WordPress interface.', 'jetpack-forms' ); ?>
					</a>
					<a class="jp-forms__view-switcher-button <?php echo $this->is_modern_view() ? 'is-active' : ''; ?>" href="<?php echo esc_url( add_query_arg( 'preferred-view', self::MODERN_VIEW, 'admin.php?page=jetpack-forms' ) ); ?>">
						<strong><?php esc_html_e( 'Inbox', 'jetpack-forms' ); ?></strong>
						<?php esc_html_e( 'The new Jetpack Forms inbox interface for form responses.', 'jetpack-forms' ); ?>
					</a>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Embed the switch styles on the page.
	 */
	public function print_styles() {
		if ( ! $this->is_visible() ) {
			return;
		}

		wp_register_style(
			'jetpack-forms-dashboard-switch',
			false,
			array(),
			JETPACK__VERSION
		);
		wp_enqueue_style( 'jetpack-forms-dashboard-switch' );

		wp_add_inline_style(
			'jetpack-forms-dashboard-switch',
			<<<CSS
			#jetpack-forms__view-link-wrap {
				float: left;
				margin: 0 0 0 6px;
			}

			.toplevel_page_jetpack-forms :not(#screen-meta-links) > #jetpack-forms__view-link-wrap {
				position: absolute;
				right: 32px;
				top: 0;
				z-index: 179;
			}

			.toplevel_page_jetpack-forms #jetpack-forms__view-link {
				background-color: #fff;
				border: 1px solid #c3c4c7;
				border-top: none;
				border-radius: 0 0 4px 4px;
				color: #646970;
				cursor: pointer;
				font-size: 13px;
				line-height: 1.7;
				padding: 3px 6px 3px 16px;
			}

			.toplevel_page_jetpack-forms #jetpack-forms__view-link::after {
				right: 0;
				content: "\\f140";
				font: normal 20px/1 dashicons;
				speak: never;
				display: inline-flex;
				padding: 0 5px 0 0;
				bottom: 2px;
				position: relative;
				vertical-align: bottom;
				-webkit-font-smoothing: antialiased;
				-moz-osx-font-smoothing: grayscale;
				text-decoration: none;
			}

			.screen-options-tab__wrapper {
				position:relative
			}

			.screen-options-tab__dropdown {
				background-color: #fff;
				border: 1px solid var(--color-neutral-5);
				border-radius: 4px;
				box-shadow: 0 4px 10px #0000001a;
				padding: 3px;
				position: absolute;
				right: 20px;
				top: 37px;
				width:215px;
				z-index: 9999;
			}

			@media screen and (max-width: 782px) {
				.screen-options-tab__dropdown {
					right: 10px;
					top: 47px;
				}
			}

			@media screen and (max-width: 600px) {
				.screen-options-tab__dropdown {
					top: 93px;
				}

				.toplevel_page_jetpack-forms :not(#screen-meta-links) > #jetpack-forms__view-link-wrap {
					top: var(--wp-admin--admin-bar--height);
				}
			}

			.jp-forms__view-switcher:not(:hover) .jp-forms__view-switcher-button:nth-child(2) > strong {
				color:var(--wp-admin-theme-color)
			}

			.jp-forms__view-switcher-button, a.jp-forms__view-switcher-button {
				background: transparent;
				border: 1px solid #0000;
				border-radius: 4px;
				color: var(--color-text);
				cursor: pointer;
				display: inline-block;
				font-size: .75rem;
				line-height: normal;
				text-decoration: none;
				padding: 8px;
				text-align:left
			}

			a.jp-forms__view-switcher-button.is-active {
				border-color: var(--wp-admin-theme-color);
				margin-bottom:4px
			}

			.jp-forms__view-switcher-button:last-child, a.jp-forms__view-switcher-button:last-child {
				margin-bottom:0
			}

			.jp-forms__view-switcher-button strong, a.jp-forms__view-switcher-button strong {
				display: block;
				font-size: 13px;
				margin-bottom:4px
			}

			.jp-forms__view-switcher-button:focus > strong, .jp-forms__view-switcher-button:hover > strong, a.jp-forms__view-switcher-button:focus > strong, a.jp-forms__view-switcher-button:hover > strong {
				color:var(--wp-admin-theme-color)
			}
CSS
		);
	}

	/**
	 * Add scripts for the switch component.
	 */
	public function add_scripts() {
		if ( ! $this->is_visible() ) {
			return;
		}

		wp_add_inline_script(
			'common',
			"(function( $ ) {
				$( '#jetpack-forms__view-link-wrap' ).appendTo( '#screen-meta-links' );

				var viewLink = $( '#jetpack-forms__view-link' );
				var viewWrap = $( '#jetpack-forms__view-wrap' );

				viewLink.on( 'click', function() {
					viewWrap.toggle();
					viewLink.toggleClass( 'screen-meta-active' );
				} );

				$( document ).on( 'mouseup', function( event ) {
					if ( ! viewLink.is( event.target ) && ! viewWrap.is( event.target ) && viewWrap.has( event.target ).length === 0 ) {
						viewWrap.hide();
						viewLink.removeClass( 'screen-meta-active' );
					}
				});
			})( jQuery );"
		);
	}

	/**
	 * Updates the prefeerred view setting for the user if a GET param is present.
	 */
	public function handle_preferred_view() {
		// For simplicity, we only treat this as a valid operation
		// if it occurs on one of the screens with the switch active.
		// phpcs:disable WordPress.Security.NonceVerification
		if ( ! $this->is_visible() || ! isset( $_GET['preferred-view'] ) ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification
		$view = sanitize_key( $_GET['preferred-view'] );

		if ( ! in_array( $view, array( self::CLASSIC_VIEW, self::MODERN_VIEW ), true ) ) {
			return;
		}

		update_user_option( get_current_user_id(), 'jetpack_forms_admin_preferred_view', $view );
		wp_safe_redirect( remove_query_arg( 'preferred-view' ) );
		exit;
	}

	/**
	 * Returns the preferred feedback view for the current user.
	 *
	 * @return string
	 */
	public function get_preferred_view() {
		$preferred_view = get_user_option( 'jetpack_forms_admin_preferred_view' );

		return in_array( $preferred_view, array( self::CLASSIC_VIEW, self::MODERN_VIEW ), true ) ? $preferred_view : self::MODERN_VIEW;
	}

	/**
	 * Returns true if the switch should be visible on the current page.
	 *
	 * @return boolean
	 */
	public function is_visible() {
		return Jetpack_Forms::is_feedback_dashboard_enabled() && (
			$this->is_classic_view() ||
			$this->is_modern_view()
		);
	}

	/**
	 * Returns true if the given screen features the classic view.
	 *
	 * @return boolean
	 */
	public function is_classic_view() {
		$screen = get_current_screen();

		return $screen && $screen->id === 'edit-feedback';
	}

	/**
	 * Returns true if the given screen features the modern view.
	 *
	 * @return boolean
	 */
	public function is_modern_view() {
		$screen = get_current_screen();

		// When classic view is set as preferred, jetpack-forms is registered under an empty parrent so it doesn't appear in the menu.
		// Because of this, we need to support these two screens.
		return $screen && in_array( $screen->id, array( 'admin_page_jetpack-forms', 'toplevel_page_jetpack-forms' ), true );
	}
}
