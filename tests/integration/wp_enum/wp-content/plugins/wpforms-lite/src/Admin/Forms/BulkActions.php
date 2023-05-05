<?php

namespace WPForms\Admin\Forms;

use WPForms\Admin\Notice;

/**
 * Bulk actions on All Forms page.
 *
 * @since 1.7.3
 */
class BulkActions {

	/**
	 * Allowed actions.
	 *
	 * @since 1.7.3
	 *
	 * @const array
	 */
	const ALLOWED_ACTIONS = [
		'trash',
		'restore',
		'delete',
		'duplicate',
		'empty_trash',
	];

	/**
	 * Forms ids.
	 *
	 * @since 1.7.3
	 *
	 * @var array
	 */
	private $ids;

	/**
	 * Current action.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $action;

	/**
	 * Current view.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $view;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.7.3
	 *
	 * @return bool
	 */
	private function allow_load() {

		// Load only on the `All Forms` admin page.
		return wpforms_is_admin_page( 'overview' );
	}

	/**
	 * Initialize class.
	 *
	 * @since 1.7.3
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->view = wpforms()->get( 'forms_views' )->get_current_view();

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		add_action( 'load-toplevel_page_wpforms-overview', [ $this, 'notices' ] );
		add_action( 'load-toplevel_page_wpforms-overview', [ $this, 'process' ] );
		add_filter( 'removable_query_args', [ $this, 'removable_query_args' ] );
	}

	/**
	 * Process the bulk actions.
	 *
	 * @since 1.7.3
	 */
	public function process() {

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$this->ids    = isset( $_GET['form_id'] ) ? array_map( 'absint', (array) $_GET['form_id'] ) : [];
		$this->action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : false;

		if ( $this->action === '-1' ) {
			$this->action = ! empty( $_REQUEST['action2'] ) ? sanitize_key( $_REQUEST['action2'] ) : false;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( empty( $this->ids ) || empty( $this->action ) ) {
			return;
		}

		// Check exact action values.
		if ( ! in_array( $this->action, self::ALLOWED_ACTIONS, true ) ) {
			return;
		}

		if ( empty( $_GET['_wpnonce'] ) ) {
			return;
		}

		// Check the nonce.
		if (
			! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'bulk-forms' ) &&
			! wp_verify_nonce( sanitize_key( $_GET['_wpnonce'] ), 'wpforms_' . $this->action . '_form_nonce' )
		) {
			return;
		}

		// Finally, we can process the action.
		$this->process_action();
	}

	/**
	 * Process action.
	 *
	 * @since 1.7.3
	 *
	 * @uses process_action_trash
	 * @uses process_action_restore
	 * @uses process_action_delete
	 * @uses process_action_duplicate
	 * @uses process_action_empty_trash
	 */
	private function process_action() {

		$method = "process_action_{$this->action}";

		// Check that we have a method for this action.
		if ( ! method_exists( $this, $method ) ) {
			return;
		}

		if ( empty( $this->ids ) || ! is_array( $this->ids ) ) {
			return;
		}

		$result = [];

		foreach ( $this->ids as $id ) {
			$result[ $id ] = $this->$method( $id );
		}

		$count_result = count( array_keys( array_filter( $result ) ) );

		// Empty trash action returns count of deleted forms.
		if ( $method === 'process_action_empty_trash' ) {
			$count_result = isset( $result[1] ) ? $result[1] : 0;
		}

		// Unset get vars and perform redirect to avoid action reuse.
		wp_safe_redirect(
			add_query_arg(
				rtrim( $this->action, 'e' ) . 'ed',
				$count_result,
				remove_query_arg( [ 'action', 'action2', '_wpnonce', 'form_id', 'paged', '_wp_http_referer' ] )
			)
		);
		exit;
	}

	/**
	 * Trash the form.
	 *
	 * @since 1.7.3
	 *
	 * @param int $id Form ID to trash.
	 *
	 * @return bool
	 */
	private function process_action_trash( $id ) {

		return wpforms()->get( 'form' )->update_status( $id, 'trash' );
	}

	/**
	 * Restore the form.
	 *
	 * @since 1.7.3
	 *
	 * @param int $id Form ID to restore from trash.
	 *
	 * @return bool
	 */
	private function process_action_restore( $id ) {

		return wpforms()->get( 'form' )->update_status( $id, 'publish' );
	}

	/**
	 * Delete the form.
	 *
	 * @since 1.7.3
	 *
	 * @param int $id Form ID to delete.
	 *
	 * @return bool
	 */
	private function process_action_delete( $id ) {

		return wpforms()->get( 'form' )->delete( $id );
	}

	/**
	 * Duplicate the form.
	 *
	 * @since 1.7.3
	 *
	 * @param int $id Form ID to duplicate.
	 *
	 * @return bool
	 */
	private function process_action_duplicate( $id ) {

		if ( ! wpforms_current_user_can( 'create_forms' ) ) {
			return false;
		}

		if ( ! wpforms_current_user_can( 'view_form_single', $id ) ) {
			return false;
		}

		return wpforms()->get( 'form' )->duplicate( $id );
	}

	/**
	 * Empty trash.
	 *
	 * @since 1.7.3
	 *
	 * @param int $id Form ID. This parameter is not used in this method,
	 *                but we need to keep it here because all the `process_action_*` methods
	 *                should be called with the $id parameter.
	 *
	 * @return bool
	 */
	private function process_action_empty_trash( $id ) {

		// Empty trash is actually the "delete all forms in trash" action.
		// So, after the execution we should display the same notice as for the `delete` action.
		$this->action = 'delete';

		return wpforms()->get( 'form' )->empty_trash();
	}

	/**
	 * Define bulk actions available for forms overview table.
	 *
	 * @since 1.7.3
	 *
	 * @return array
	 */
	public function get_dropdown_items() {

		$items = [];

		if ( wpforms_current_user_can( 'delete_forms' ) ) {
			if ( $this->view === 'trash' ) {
				$items = [
					'restore' => esc_html__( 'Restore', 'wpforms-lite' ),
					'delete'  => esc_html__( 'Delete Permanently', 'wpforms-lite' ),
				];
			} else {
				$items = [
					'trash' => esc_html__( 'Trash', 'wpforms-lite' ),
				];
			}
		}

		// phpcs:disable WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity

		/**
		 * Filters the Bulk Actions dropdown items.
		 *
		 * @since 1.7.5
		 *
		 * @param array $items Dropdown items.
		 */
		$items = apply_filters( 'wpforms_admin_forms_bulk_actions_get_dropdown_items', $items );

		// phpcs:enable WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity

		if ( empty( $items ) ) {
			// We should have dummy item, otherwise, WP will hide the Bulk Actions Dropdown,
			// which is not good from a design point of view.
			return [
				'' => '&mdash;',
			];
		}

		return $items;
	}

	/**
	 * Admin notices.
	 *
	 * @since 1.7.3
	 */
	public function notices() {

		// phpcs:disable WordPress.Security.NonceVerification
		$results = [
			'trashed'    => ! empty( $_REQUEST['trashed'] ) ? sanitize_key( $_REQUEST['trashed'] ) : false,
			'restored'   => ! empty( $_REQUEST['restored'] ) ? sanitize_key( $_REQUEST['restored'] ) : false,
			'deleted'    => ! empty( $_REQUEST['deleted'] ) ? sanitize_key( $_REQUEST['deleted'] ) : false,
			'duplicated' => ! empty( $_REQUEST['duplicated'] ) ? sanitize_key( $_REQUEST['duplicated'] ) : false,
		];
		// phpcs:enable WordPress.Security.NonceVerification

		// Display notice in case of error.
		if ( in_array( 'error', $results, true ) ) {
			Notice::add(
				esc_html__( 'Security check failed. Please try again.', 'wpforms-lite' ),
				'error'
			);

			return;
		}

		$this->notices_success( $results );
	}

	/**
	 * Admin success notices.
	 *
	 * @since 1.7.3
	 *
	 * @param array $results Action results data.
	 */
	private function notices_success( $results ) {

		if ( ! empty( $results['trashed'] ) ) {
			$notice = sprintf( /* translators: %d - Trashed forms count. */
				_n( '%d form was successfully moved to Trash.', '%d forms were successfully moved to Trash.', (int) $results['trashed'], 'wpforms-lite' ),
				(int) $results['trashed']
			);
		}

		if ( ! empty( $results['restored'] ) ) {
			$notice = sprintf( /* translators: %d - Restored forms count. */
				_n( '%d form was successfully restored.', '%d forms were successfully restored.', (int) $results['restored'], 'wpforms-lite' ),
				(int) $results['restored']
			);
		}

		if ( ! empty( $results['deleted'] ) ) {
			$notice = sprintf( /* translators: %d - Deleted forms count. */
				_n( '%d form was successfully permanently deleted.', '%d forms were successfully permanently deleted.', (int) $results['deleted'], 'wpforms-lite' ),
				(int) $results['deleted']
			);
		}

		if ( ! empty( $results['duplicated'] ) ) {
			$notice = sprintf( /* translators: %d - Duplicated forms count. */
				_n( '%d form was successfully duplicated.', '%d forms were successfully duplicated.', (int) $results['duplicated'], 'wpforms-lite' ),
				(int) $results['duplicated']
			);
		}

		if ( ! empty( $notice ) ) {
			Notice::add( $notice, 'info' );
		}
	}

	/**
	 * Remove certain arguments from a query string that WordPress should always hide for users.
	 *
	 * @since 1.7.3
	 *
	 * @param array $removable_query_args An array of parameters to remove from the URL.
	 *
	 * @return array Extended/filtered array of parameters to remove from the URL.
	 */
	public function removable_query_args( $removable_query_args ) {

		$removable_query_args[] = 'trashed';
		$removable_query_args[] = 'restored';
		$removable_query_args[] = 'deleted';
		$removable_query_args[] = 'duplicated';

		return $removable_query_args;
	}
}
