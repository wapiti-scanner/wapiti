<?php

namespace WPForms\Admin;

/**
 * Admin Flyout Menu.
 *
 * @since 1.5.7
 */
class FlyoutMenu {

	/**
	 * Constructor.
	 *
	 * @since 1.5.7
	 */
	public function __construct() {

		if ( ! \wpforms_is_admin_page() || \wpforms_is_admin_page( 'builder' ) ) {
			return;
		}

		if ( ! \apply_filters( 'wpforms_admin_flyoutmenu', true ) ) {
			return;
		}

		// Check if WPForms Challenge can be displayed.
		if ( wpforms()->get( 'challenge' )->challenge_can_start() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.5.7
	 */
	public function hooks() {

		add_action( 'admin_footer', [ $this, 'output' ] );
	}

	/**
	 * Output menu.
	 *
	 * @since 1.5.7
	 */
	public function output() {

		printf(
			'<div id="wpforms-flyout">
				<div id="wpforms-flyout-items">
					%1$s
				</div>
				<a href="#" class="wpforms-flyout-button wpforms-flyout-head">
					<div class="wpforms-flyout-label">%2$s</div>
					<img src="%3$s" alt="%2$s" data-active="%4$s" />
				</a>
			</div>',
			$this->get_items_html(), // phpcs:ignore
			\esc_attr__( 'See Quick Links', 'wpforms-lite' ),
			\esc_url( \WPFORMS_PLUGIN_URL . 'assets/images/admin-flyout-menu/sullie-default.svg' ),
			\esc_url( \WPFORMS_PLUGIN_URL . 'assets/images/admin-flyout-menu/sullie-active.svg' )
		);
	}

	/**
	 * Generate menu items HTML.
	 *
	 * @since 1.5.7
	 *
	 * @return string Menu items HTML.
	 */
	private function get_items_html() {

		$items      = array_reverse( $this->menu_items() );
		$items_html = '';

		foreach ( $items as $item_key => $item ) {
			$items_html .= sprintf(
				'<a href="%1$s" target="_blank" rel="noopener noreferrer" class="wpforms-flyout-button wpforms-flyout-item wpforms-flyout-item-%2$d"%5$s%6$s>
					<div class="wpforms-flyout-label">%3$s</div>
					<i class="fa %4$s"></i>
				</a>',
				\esc_url( $item['url'] ),
				(int) $item_key,
				\esc_html( $item['title'] ),
				\sanitize_html_class( $item['icon'] ),
				! empty( $item['bgcolor'] ) ? ' style="background-color: ' . \esc_attr( $item['bgcolor'] ) . '"' : '',
				! empty( $item['hover_bgcolor'] ) ? ' onMouseOver="this.style.backgroundColor=\'' . \esc_attr( $item['hover_bgcolor'] ) . '\'" onMouseOut="this.style.backgroundColor=\'' . \esc_attr( $item['bgcolor'] ) . '\'"' : ''
			);
		}

		return $items_html;
	}

	/**
	 * Menu items data.
	 *
	 * @since 1.5.7
	 */
	private function menu_items() {

		$is_pro = wpforms()->is_pro();

		$utm_campaign = $is_pro ? 'plugin' : 'liteplugin';

		$items = [
			[
				'title'         => \esc_html__( 'Upgrade to WPForms Pro', 'wpforms-lite' ),
				'url'           => wpforms_admin_upgrade_link( 'Flyout Menu', 'Upgrade to WPForms Pro' ),
				'icon'          => 'fa-star',
				'bgcolor'       => '#E1772F',
				'hover_bgcolor' => '#ff8931',
			],
			[
				'title' => \esc_html__( 'Support & Docs', 'wpforms-lite' ),
				'url'   => 'https://wpforms.com/docs/?utm_source=WordPress&utm_medium=Flyout Menu&utm_campaign=' . $utm_campaign . '&utm_content=Support',
				'icon'  => 'fa-life-ring',
			],
			[
				'title' => \esc_html__( 'Join Our Community', 'wpforms-lite' ),
				'url'   => 'https://www.facebook.com/groups/wpformsvip/',
				'icon'  => 'fa-comments',
			],
			[
				'title' => \esc_html__( 'Suggest a Feature', 'wpforms-lite' ),
				'url'   => 'https://wpforms.com/features/suggest/?utm_source=WordPress&utm_medium=Flyout Menu&utm_campaign=' . $utm_campaign . '&utm_content=Feature',
				'icon'  => 'fa-lightbulb-o',
			],
		];

		if ( $is_pro ) {
			array_shift( $items );
		}

		return \apply_filters( 'wpforms_admin_flyout_menu_items', $items );
	}
}
