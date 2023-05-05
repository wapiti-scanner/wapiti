<?php

/**
 * Admin notices, on the fly.
 *
 * @example
 * WPForms_Admin_Notice::success( 'All is good!' );
 *
 * @example
 * WPForms_Admin_Notice::warning( 'Do something please.' );
 *
 * @since 1.3.9
 * @deprecated 1.7.2
 */
class WPForms_Admin_Notice {

	/**
	 * Single instance holder.
	 *
	 * @since 1.3.9
	 * @var mixed
	 */
	private static $_instance = null;

	/**
	 * Added notices.
	 *
	 * @since 1.3.9
	 * @var array
	 */
	public $notices = [];

	/**
	 * Get the instance.
	 *
	 * @since 1.3.9
	 * @return WPForms_Admin_Notice
	 */
	public static function getInstance() {

		if ( self::$_instance === null ) {
			self::$_instance = new WPForms_Admin_Notice();
		}

		return self::$_instance;
	}

	/**
	 * Hook when called.
	 *
	 * @since 1.3.9
	 */
	public function __construct() {

		_deprecated_function( __METHOD__, '1.7.2 of the WPForms plugin' );

		add_action( 'admin_notices', [ &$this, 'display' ] );
	}

	/**
	 * Display the notices.
	 *
	 * @since 1.3.9
	 */
	public function display() {

		// At least one WPForms capability is needed to see admin notices.
		if ( ! wpforms_current_user_can( 'any' ) ) {
			return;
		}

		echo implode( ' ', $this->notices );
	}

	/**
	 * Add notice to instance property.
	 *
	 * @since 1.3.9
	 *
	 * @param string $message Message to display.
	 * @param string $type    Type of the notice (default: '').
	 */
	public static function add( $message, $type = '' ) {

		_deprecated_function( __METHOD__, '1.7.2 of the WPForms plugin' );

		$instance = self::getInstance();
		$id       = 'wpforms-notice-' . ( count( $instance->notices ) + 1 );
		$type     = ! empty( $type ) ? 'notice-' . $type : '';
		$notice   = sprintf( '<div class="notice wpforms-notice %s" id="%s">%s</div>', $type, $id, wpautop( $message ) );

		$instance->notices[] = $notice;
	}

	/**
	 * Add Info notice.
	 *
	 * @since 1.3.9
	 *
	 * @param string $message Message to display.
	 */
	public static function info( $message ) {
		self::add( $message, 'info' );
	}

	/**
	 * Add Error notice.
	 *
	 * @since 1.3.9
	 *
	 * @param string $message Message to display.
	 */
	public static function error( $message ) {
		self::add( $message, 'error' );
	}

	/**
	 * Add Success notice.
	 *
	 * @since 1.3.9
	 *
	 * @param string $message Message to display.
	 */
	public static function success( $message ) {
		self::add( $message, 'success' );
	}

	/**
	 * Add Warning notice.
	 *
	 * @since 1.3.9
	 *
	 * @param string $message Message to display.
	 */
	public static function warning( $message ) {
		self::add( $message, 'warning' );
	}
}
