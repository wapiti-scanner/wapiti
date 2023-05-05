<?php

namespace WPForms\Logger;

/**
 * Class Log.
 *
 * @since 1.6.3
 */
class Log {

	/**
	 * Repository.
	 *
	 * @since 1.6.3
	 *
	 * @var Repository
	 */
	private $repository;

	/**
	 * List table.
	 *
	 * @since 1.6.3
	 *
	 * @var ListTable
	 */
	private $list_table;

	/**
	 * Register log hooks.
	 *
	 * @since 1.6.3
	 */
	public function hooks() {

		$this->repository = new Repository( new RecordQuery() );

		add_action( 'shutdown', [ $this->repository, 'save' ] );

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_styles' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
		add_action( 'wp_ajax_wpforms_get_log_record', [ $this, 'get_record' ] );
	}

	/**
	 * Enqueue styles.
	 *
	 * @since 1.6.3
	 */
	public function enqueue_styles() {

		if ( ! $this->is_logger_page() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-tools-logger',
			WPFORMS_PLUGIN_URL . "assets/css/logger{$min}.css",
			[],
			WPFORMS_VERSION,
			'all'
		);
	}

	/**
	 * Enqueue styles.
	 *
	 * @since 1.6.3
	 */
	public function enqueue_scripts() {

		if ( ! $this->is_logger_page() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-tools-logger',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/logger/logger{$min}.js",
			[ 'jquery', 'jquery-confirm', 'wp-util' ],
			WPFORMS_VERSION,
			true
		);
	}

	/**
	 * Get log types.
	 *
	 * @since 1.6.3
	 *
	 * @return array
	 */
	public static function get_log_types() {

		return [
			'conditional_logic' => esc_html__( 'Conditional Logic', 'wpforms-lite' ),
			'entry'             => esc_html__( 'Entries', 'wpforms-lite' ),
			'error'             => esc_html__( 'Errors', 'wpforms-lite' ),
			'payment'           => esc_html__( 'Payment', 'wpforms-lite' ),
			'provider'          => esc_html__( 'Providers', 'wpforms-lite' ),
			'security'          => esc_html__( 'Security', 'wpforms-lite' ),
			'spam'              => esc_html__( 'Spam', 'wpforms-lite' ),
			'log'               => esc_html__( 'Log', 'wpforms-lite' ),
		];
	}

	/**
	 * Determine if it a Logs page.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	private function is_logger_page() {

		return wpforms_is_admin_page( 'tools', 'logs' );
	}

	/**
	 * Create new record.
	 *
	 * @since 1.6.3
	 *
	 * @param string       $title    Record title.
	 * @param string       $message  Record message.
	 * @param array|string $types    Array, string, or string separated by commas types.
	 * @param int          $form_id  Record form ID.
	 * @param int          $entry_id Record entry ID.
	 * @param int          $user_id  Record user ID.
	 */
	public function add( $title, $message, $types, $form_id = 0, $entry_id = 0, $user_id = 0 ) {

		$this->repository->add( $title, $message, $types, $form_id, $entry_id, $user_id );
	}

	/**
	 * Create table for logs.
	 *
	 * @since 1.6.3
	 */
	public function create_table() {

		$this->repository->create_table();
	}

	/**
	 * Get ListView.
	 *
	 * @since 1.6.3
	 *
	 * @return ListTable
	 */
	public function get_list_table() { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		if ( ! $this->list_table ) {
			$this->list_table = new ListTable( $this->repository );

			add_action( 'admin_print_scripts', [ $this->list_table, 'popup_template' ] );
		}

		return $this->list_table;
	}

	/**
	 * Json config for detail information about log record.
	 *
	 * @since 1.6.3
	 */
	public function get_record() {

		if (
			! check_ajax_referer( 'wpforms-admin', 'nonce', false ) ||
			! wpforms_current_user_can()
		) {
			wp_send_json_error( esc_html__( 'You do not have permission.', 'wpforms-lite' ) );
		}

		$id = filter_input( INPUT_GET, 'recordId', FILTER_VALIDATE_INT );

		if ( ! $id ) {
			wp_send_json_error( esc_html__( 'Record ID not found', 'wpforms-lite' ), 404 );
		}

		$item = $this->repository->record( $id );

		if ( $item === null ) {
			wp_send_json_error( esc_html__( 'No such record.', 'wpforms-lite' ), 404 );
		}

		wp_send_json_success(
			[
				'ID'        => absint( $item->get_id() ),
				'title'     => esc_html( $item->get_title() ),
				'message'   => wp_kses( $item->get_message(), [ 'pre' => [] ] ),
				'types'     => esc_html( implode( ', ', $item->get_types( 'label' ) ) ),
				'create_at' => esc_html( $item->get_date( 'full' ) ),
				'form_id'   => absint( $item->get_form_id() ),
				'entry_id'  => absint( $item->get_entry_id() ),
				'user_id'   => absint( $item->get_user_id() ),
				'form_url'  => admin_url( sprintf( 'admin.php?page=wpforms-builder&view=fields&form_id=%d', absint( $item->get_form_id() ) ) ),
				'entry_url' => admin_url( sprintf( 'admin.php?page=wpforms-entries&view=details&entry_id=%d', absint( $item->get_entry_id() ) ) ),
				'user_url'  => esc_url( get_edit_user_link( $item->get_user_id() ) ),
			]
		);
	}
}
