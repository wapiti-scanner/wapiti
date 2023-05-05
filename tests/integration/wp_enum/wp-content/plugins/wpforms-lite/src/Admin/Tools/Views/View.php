<?php

namespace WPForms\Admin\Tools\Views;

use WPForms\Admin\Tools\Tools;

/**
 * Single View class.
 *
 * @since 1.6.6
 */
abstract class View {

	/**
	 * View slug.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	protected $slug;

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	abstract public function init();

	/**
	 * Get link to the view page.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	public function get_link() {

		return add_query_arg(
			[
				'page' => Tools::SLUG,
				'view' => $this->slug,
			],
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Get view label.
	 *
	 * @since 1.6.6
	 *
	 * @return string
	 */
	abstract public function get_label();

	/**
	 * Checking user capability to view.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	abstract public function check_capability();

	/**
	 * Checking if needs display in navigation.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function hide_from_nav() {

		return false;
	}

	/**
	 * Checking if navigation needs display.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function show_nav() {

		return true;
	}

	/**
	 * Display nonce field.
	 *
	 * @since 1.6.6
	 */
	public function nonce_field() {

		wp_nonce_field( 'wpforms_' . $this->slug . '_nonce', 'wpforms-tools-' . $this->slug . '-nonce' );
	}

	/**
	 * Verify nonce field.
	 *
	 * @since 1.6.6
	 */
	public function verify_nonce() {

		return ! empty( $_POST[ 'wpforms-tools-' . $this->slug . '-nonce' ] ) && wp_verify_nonce( sanitize_key( $_POST[ 'wpforms-tools-' . $this->slug . '-nonce' ] ), 'wpforms_' . $this->slug . '_nonce' );
	}

	/**
	 * Display view content.
	 *
	 * @since 1.6.6
	 */
	abstract public function display();
}
