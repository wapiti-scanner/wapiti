<?php

namespace WPForms\Admin;

use WP_Admin_Bar;

/**
 * WPForms admin bar menu.
 *
 * @since 1.6.0
 */
class AdminBarMenu {

	/**
	 * Initialize class.
	 *
	 * @since 1.6.0
	 */
	public function init() {

		if ( ! $this->has_access() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.6.0
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_css' ] );
		add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_css' ] );
		add_action( 'wp_enqueue_scripts', [ $this, 'enqueue_js' ] );

		add_action( 'admin_bar_menu', [ $this, 'register' ], 999 );
		add_action( 'wpforms_wp_footer_end', [ $this, 'menu_forms_data_html' ] );
	}

	/**
	 * Determine whether the current user has access to see admin bar menu.
	 *
	 * @since 1.6.0
	 *
	 * @return bool
	 */
	public function has_access() {

		$access = false;

		if (
			is_admin_bar_showing() &&
			wpforms_current_user_can() &&
			! wpforms_setting( 'hide-admin-bar', false )
		) {
			$access = true;
		}

		return (bool) apply_filters( 'wpforms_admin_adminbarmenu_has_access', $access );
	}

	/**
	 * Determine whether new notifications are available.
	 *
	 * @since 1.6.0
	 *
	 * @return bool
	 */
	public function has_notifications() {

		return wpforms()->get( 'notifications' )->get_count();
	}

	/**
	 * Enqueue CSS styles.
	 *
	 * @since 1.6.0
	 */
	public function enqueue_css() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-admin-bar',
			WPFORMS_PLUGIN_URL . "assets/css/admin-bar{$min}.css",
			[],
			WPFORMS_VERSION
		);

		// Apply WordPress pre/post 5.7 accent color, only when admin bar is displayed on the frontend or we're
		// inside the Form Builder - it does not load some WP core admin styles, including themes.
		if ( wpforms_is_admin_page( 'builder' ) || ! is_admin() ) {
			wp_add_inline_style(
				'wpforms-admin-bar',
				sprintf(
					'#wpadminbar .wpforms-menu-notification-counter, #wpadminbar .wpforms-menu-notification-indicator { 
						background-color: %s !important;
						color: #ffffff !important; 
					}',
					version_compare( get_bloginfo( 'version' ), '5.7', '<' ) ? '#ca4a1f' : '#d63638'
				)
			);
		}
	}

	/**
	 * Enqueue JavaScript files.
	 *
	 * @since 1.6.5
	 */
	public function enqueue_js() {

		// In WordPress 5.3.1 the `admin-bar.js` file was rewritten and removed all jQuery dependencies.
		$is_wp_531_plus = version_compare( get_bloginfo( 'version' ), '5.3.1', '>=' );
		$inline_script  = sprintf(
			"( function() {
				function wpforms_admin_bar_menu_init() {
					var template = document.getElementById( 'tmpl-wpforms-admin-menubar-data' ),
						notifications = document.getElementById( 'wp-admin-bar-wpforms-notifications' );

					if ( ! template ) {
						return;
					}

					if ( ! notifications ) {
						var menu = document.getElementById( 'wp-admin-bar-wpforms-menu-default' );

						if ( ! menu ) {
							return;
						}

						menu.insertAdjacentHTML( 'afterBegin', template.innerHTML );
					} else {
						notifications.insertAdjacentHTML( 'afterend', template.innerHTML );
					}
				};
				%s
			}() );",
			$is_wp_531_plus ? "document.addEventListener( 'DOMContentLoaded', wpforms_admin_bar_menu_init );" : "if ( typeof( jQuery ) != 'undefined' ) { jQuery( wpforms_admin_bar_menu_init ); } else { document.addEventListener( 'DOMContentLoaded', wpforms_admin_bar_menu_init ); }"
		);

		wp_add_inline_script( 'admin-bar', $inline_script, 'before' );
	}

	/**
	 * Register and render admin bar menu items.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function register( WP_Admin_Bar $wp_admin_bar ) {

		$items = (array) apply_filters(
			'wpforms_admin_adminbarmenu_register',
			[
				'main_menu',
				'notification_menu',
				'all_forms_menu',
				'add_new_menu',
				'community_menu',
				'support_menu',
			],
			$wp_admin_bar
		);

		foreach ( $items as $item ) {

			$this->{ $item }( $wp_admin_bar );

			do_action( "wpforms_admin_adminbarmenu_register_{$item}_after", $wp_admin_bar );
		}
	}

	/**
	 * Render primary top-level admin bar menu item.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function main_menu( WP_Admin_Bar $wp_admin_bar ) {

		$indicator     = '';
		$notifications = $this->has_notifications();

		if ( $notifications ) {
			$count     = $notifications < 10 ? $notifications : '!';
			$indicator = ' <div class="wp-core-ui wp-ui-notification wpforms-menu-notification-counter">' . $count . '</div>';
		}

		$wp_admin_bar->add_menu(
			[
				'id'    => 'wpforms-menu',
				'title' => 'WPForms' . $indicator,
				'href'  => admin_url( 'admin.php?page=wpforms-overview' ),
			]
		);
	}

	/**
	 * Render Notifications admin bar menu item.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function notification_menu( WP_Admin_Bar $wp_admin_bar ) {

		if ( ! $this->has_notifications() ) {
			return;
		}

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-notifications',
				'title'  => esc_html__( 'Notifications', 'wpforms-lite' ) . ' <div class="wp-core-ui wp-ui-notification wpforms-menu-notification-indicator"></div>',
				'href'   => admin_url( 'admin.php?page=wpforms-overview' ),
			]
		);
	}

	/**
	 * Render All Forms admin bar menu item.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function all_forms_menu( WP_Admin_Bar $wp_admin_bar ) {

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-forms',
				'title'  => esc_html__( 'All Forms', 'wpforms-lite' ),
				'href'   => admin_url( 'admin.php?page=wpforms-overview' ),
			]
		);
	}

	/**
	 * Render Add New admin bar menu item.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function add_new_menu( WP_Admin_Bar $wp_admin_bar ) {

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-add-new',
				'title'  => esc_html__( 'Add New', 'wpforms-lite' ),
				'href'   => admin_url( 'admin.php?page=wpforms-builder' ),
			]
		);
	}

	/**
	 * Render Community admin bar menu item.
	 *
	 * @since 1.6.0
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function community_menu( WP_Admin_Bar $wp_admin_bar ) {

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-community',
				'title'  => esc_html__( 'Community', 'wpforms-lite' ),
				'href'   => 'https://www.facebook.com/groups/wpformsvip/',
				'meta'   => [
					'target' => '_blank',
					'rel'    => 'noopener noreferrer',
				],
			]
		);
	}

	/**
	 * Render Support admin bar menu item.
	 *
	 * @since 1.6.0
	 * @since 1.7.4 Update the `Support` item title to `Help Docs`.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function support_menu( WP_Admin_Bar $wp_admin_bar ) {

		$href = add_query_arg(
			[
				'utm_campaign' => wpforms()->is_pro() ? 'plugin' : 'liteplugin',
				'utm_medium'   => 'admin-bar',
				'utm_source'   => 'WordPress',
				'utm_content'  => 'Documentation',
			],
			'https://wpforms.com/docs/'
		);

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-help-docs',
				'title'  => esc_html__( 'Help Docs', 'wpforms-lite' ),
				'href'   => $href,
				'meta'   => [
					'target' => '_blank',
					'rel'    => 'noopener noreferrer',
				],
			]
		);
	}

	/**
	 * Get form data for JS to modify the admin bar menu.
	 *
	 * @since 1.6.5
	 *
	 * @param array $forms Forms array.
	 *
	 * @return array
	 */
	protected function get_forms_data( $forms ) {

		$data = [
			'has_notifications' => $this->has_notifications(),
			'edit_text'         => esc_html__( 'Edit Form', 'wpforms-lite' ),
			'entry_text'        => esc_html__( 'View Entries', 'wpforms-lite' ),
			'survey_text'       => esc_html__( 'Survey Results', 'wpforms-lite' ),
			'forms'             => [],
		];

		foreach ( $forms as $form ) {
			$form_id = absint( $form['id'] );

			if ( empty( $form_id ) ) {
				continue;
			}

			/* translators: %d - Form ID */
			$form_title = sprintf( esc_html__( 'Form ID: %d', 'wpforms-lite' ), $form_id );

			if ( ! empty( $form['settings'] ) && ! empty( $form['settings']['form_title'] ) ) {
				$form_title = wp_html_excerpt(
					sanitize_text_field( $form['settings']['form_title'] ),
					99,
					'&hellip;'
				);
			}

			$data['forms'][] = apply_filters(
				'wpforms_admin_adminbarmenu_get_form_data',
				[
					'form_id'  => $form_id,
					'title'    => $form_title,
					'edit_url' => admin_url( 'admin.php?page=wpforms-builder&view=fields&form_id=' . $form_id ),
				]
			);
		}

		return $data;
	}

	/**
	 * Add form(s) data to the page.
	 *
	 * @since 1.6.5
	 *
	 * @param array $forms Forms array.
	 */
	public function menu_forms_data_html( $forms ) {

		if ( empty( $forms ) ) {
			return;
		}

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin-bar-menu',
			[
				'forms_data' => $this->get_forms_data( $forms ),
			],
			true
		);
	}
}
