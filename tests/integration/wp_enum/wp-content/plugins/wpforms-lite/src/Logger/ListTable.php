<?php

namespace WPForms\Logger;

use WP_List_Table;

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Class ListTable.
 *
 * @since 1.6.3
 */
class ListTable extends WP_List_Table {

	/**
	 * Record Query.
	 *
	 * @since 1.6.3
	 *
	 * @var Repository
	 */
	private $repository;

	/**
	 * ListTable constructor.
	 *
	 * @since 1.6.3
	 *
	 * @param Repository $repository Repository.
	 */
	public function __construct( $repository ) {

		$this->repository = $repository;

		parent::__construct(
			[
				'plural'   => esc_html__( 'Logs', 'wpforms-lite' ),
				'singular' => esc_html__( 'Log', 'wpforms-lite' ),
			]
		);

		$this->hooks();

		add_screen_option(
			'per_page',
			[ 'default' => $this->get_items_per_page( $this->get_per_page_option_name() ) ]
		);
		set_screen_options();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		add_filter(
			'set_screen_option_' . $this->get_per_page_option_name(),
			[ $this, 'set_items_per_page_option' ],
			10,
			3
		);
	}

	/**
	 * Handles setting the items_per_page option for this screen.
	 *
	 * @since 1.7.5
	 *
	 * @param mixed  $status Default false (to skip saving the current option).
	 * @param string $option Screen option name.
	 * @param int    $value  Screen option value.
	 *
	 * @return int
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function set_items_per_page_option( $status, $option, $value ) {

		return $value;
	}

	/**
	 * Whether the table has items to display or not.
	 *
	 * @since 1.6.3
	 *
	 * @return bool
	 */
	public function has_items() {

		// We can't use the empty function because it doesn't work with Countable object.
		return (bool) count( $this->items );
	}

	/**
	 * Prepares the list of items for displaying.
	 *
	 * @since 1.6.3
	 */
	public function prepare_items() {

		$offset      = $this->get_items_offset();
		$search      = $this->get_request_search_query();
		$types       = $this->get_items_type();
		$per_page    = $this->get_items_per_page( $this->get_per_page_option_name() );
		$this->items = $this->repository->records( $per_page, $offset, $search, $types );
		$total_items = $this->get_total();

		$this->set_pagination_args(
			[
				'total_items' => $total_items,
				'per_page'    => $per_page,
				'total_pages' => ceil( $total_items / $per_page ),
			]
		);
	}

	/**
	 * Return the type of records.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	private function get_items_type() {

		return filter_input( INPUT_GET, 'log_type', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
	}

	/**
	 * Return the number of items to offset/skip for this current view.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	private function get_items_offset() {

		return $this->get_items_per_page( $this->get_per_page_option_name() ) * ( $this->get_pagenum() - 1 );
	}

	/**
	 * Return the search filter for this request, if any.
	 *
	 * @since 1.6.3
	 *
	 * @return string
	 */
	private function get_request_search_query() {

		return filter_input( INPUT_GET, 's', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
	}

	/**
	 * Column title.
	 *
	 * @since 1.6.3
	 *
	 * @param Record $item List table item.
	 *
	 * @return string
	 * @noinspection PhpUnused
	 */
	public function column_log_title( $item ) {

		return sprintf(
			'<a href="#" class="js-single-log-target" data-log-id="%1$d"><strong>%2$s</strong></a>',
			absint( $item->get_id() ),
			esc_html( $item->get_title() )
		);
	}

	/**
	 * Column message.
	 *
	 * @since 1.6.3
	 *
	 * @param Record $item List table item.
	 *
	 * @return string
	 * @noinspection PhpUnused
	 */
	public function column_message( $item ) {

		$message = $item->get_message();

		if ( preg_match( '/\[body].+{"error":"(.+)"}/i', $message, $m ) ) {
			$message = $m[1];
		}

		if ( preg_match( '/\[error] =&gt; (.+)/i', $message, $m ) ) {
			$message = $m[1];
		}

		return esc_html( $this->crop_message( $message ) );
	}

	/**
	 * Column form ID.
	 *
	 * @since 1.6.3
	 *
	 * @param Record $item List table item.
	 *
	 * @return int
	 * @noinspection PhpUnused
	 */
	public function column_form_id( $item ) {

		return absint( $item->get_form_id() );
	}

	/**
	 * Column types.
	 *
	 * @since 1.6.3
	 *
	 * @param Record $item List table item.
	 *
	 * @return string
	 * @noinspection PhpUnused
	 */
	public function column_types( $item ) {

		return esc_html( implode( ', ', $item->get_types( 'label' ) ) );
	}

	/**
	 * Column date.
	 *
	 * @since 1.6.3
	 *
	 * @param Record $item List table item.
	 *
	 * @return string
	 * @noinspection PhpUnused
	 */
	public function column_date( $item ) {

		return esc_html( $item->get_date( 'sql-local' ) );
	}

	/**
	 * Crop message for preview on list table.
	 *
	 * @since 1.6.3
	 *
	 * @param string $message Message.
	 *
	 * @return string
	 */
	private function crop_message( $message ) {

		return wp_html_excerpt( $message, 97, '...' );
	}

	/**
	 * Prepares the _column_headers property which is used by WP_Table_List at rendering.
	 * It merges the columns and the sortable columns.
	 *
	 * @since 1.6.3
	 */
	private function prepare_column_headers() {

		$this->_column_headers = [
			$this->get_columns(),
			get_hidden_columns( $this->screen ),
			[],
		];
	}

	/**
	 * Return the columns names for rendering.
	 *
	 * @since 1.6.3
	 *
	 * @return array
	 */
	public function get_columns() {

		return [
			'log_title' => __( 'Log Title', 'wpforms-lite' ),
			'message'   => __( 'Message', 'wpforms-lite' ),
			'form_id'   => __( 'Form ID', 'wpforms-lite' ),
			'types'     => __( 'Types', 'wpforms-lite' ),
			'date'      => __( 'Date', 'wpforms-lite' ),
		];
	}

	/**
	 * Header before log table.
	 *
	 * @since 1.6.3
	 */
	private function header() {

		?>
		<div class="wpforms-admin-content-header">
			<h4 class="wp-heading-inline"><?php esc_html_e( 'View Logs', 'wpforms-lite' ); ?>
				<?php if ( $this->get_request_search_query() ) { ?>
					<span class="subtitle">
				<?php
				echo sprintf( /* translators: %s: search query. */
					esc_html__( 'Search results for "%s"', 'wpforms-lite' ),
					esc_html( $this->get_request_search_query() )
				);
				?>
			</span>
				<?php } ?>
			</h4>
			<?php
			$this->hidden_fields();
			$this->search_box( esc_html__( 'Search Logs', 'wpforms-lite' ), 'plugin' );
			?>
		</div>
		<?php
	}

	/**
	 * Generate the table navigation above or below the table.
	 *
	 * @since 1.6.3
	 *
	 * @param string $which Which position.
	 */
	protected function display_tablenav( $which ) {

		?>
		<div class="tablenav <?php echo esc_attr( $which ); ?>">

			<?php
			if ( $which === 'top' ) {
				$this->extra_tablenav( $which );
			}
			$this->pagination( $which );
			?>

			<br class="clear" />
		</div>
		<?php
	}

	/**
	 * Table list actions.
	 *
	 * @since 1.6.3
	 *
	 * @param string $which Position of navigation (top or bottom).
	 */
	protected function extra_tablenav( $which ) {

		if ( ! $this->get_total() ) {
			return;
		}

		$this->log_type_select();
		$this->clear_all();
	}

	/**
	 * Clear all log records.
	 *
	 * @since 1.6.3
	 */
	private function clear_all() {

		?>
		<button name="clear-all" type="submit" class="button" value="1"><?php esc_html_e( 'Delete All Logs', 'wpforms-lite' ); ?></button>
		<?php
	}

	/**
	 * Update URL when table showing.
	 * _wp_http_referer is used only on bulk actions, we remove it to keep the $_GET shorter.
	 *
	 * @since 1.6.3
	 */
	public function process_admin_ui() {

		$uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_REQUEST['_wp_http_referer'] ) || ! empty( $_REQUEST['clear-all'] ) ) {

			if ( ! empty( $_REQUEST['clear-all'] ) ) {
				$this->repository->clear_all();
			}

			wp_safe_redirect(
				remove_query_arg(
					[ '_wp_http_referer', '_wpnonce', 'clear-all' ],
					$uri
				)
			);

			exit;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Message to be displayed when there are no items.
	 *
	 * @since 1.6.3
	 */
	public function no_items() {

		esc_html_e( 'No logs found.', 'wpforms-lite' );
	}

	/**
	 * Print all hidden fields.
	 *
	 * @since 1.6.3
	 */
	private function hidden_fields() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( $_GET as $key => $value ) {

			if ( $key[0] === '_' || $key === 'paged' || $key === 'ID' ) {
				continue;
			}

			echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( $value ) . '" />';
		}
	}

	/**
	 * Select for choose a log type.
	 *
	 * @since 1.6.3
	 */
	private function log_type_select() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$current_type = ! empty( $_GET['log_type'] ) ? sanitize_text_field( wp_unslash( $_GET['log_type'] ) ) : '';
		?>
		<select name="log_type">
			<option value=""><?php esc_html_e( 'All Logs', 'wpforms-lite' ); ?></option>
			<?php foreach ( Log::get_log_types() as $type_slug => $type ) { ?>
				<option
					value="<?php echo esc_attr( $type_slug ); ?>"
					<?php selected( $type_slug, $current_type ); ?>>
					<?php echo esc_html( $type ); ?>
				</option>
			<?php } ?>
		</select>
		<input type="submit" class="button" value="<?php esc_attr_e( 'Apply', 'wpforms-lite' ); ?>">
		<?php
	}

	/**
	 * Popup view.
	 *
	 * @since 1.6.3
	 */
	public function popup_template() {

		?>
		<script type="text/html" id="tmpl-wpforms-log-record">
			<div class="wpforms-log-popup">
				<div class="wpforms-log-popup-block">
					<div class="wpforms-log-popup-label"><?php esc_html_e( 'Log Title', 'wpforms-lite' ); ?></div>
					<div class="wpforms-log-popup-title">{{ data.title }}</div>
				</div>
				<div class="wpforms-log-popup-block">
					<div class="wpforms-log-popup-label"><?php esc_html_e( 'Message', 'wpforms-lite' ); ?></div>
					<div class="wpforms-log-popup-message">{{{ data.message }}}</div>
				</div>
				<div class="wpforms-log-popup-flex wpforms-log-popup-flex-column-2">
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'Date', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-create-at">{{ data.create_at }}</div>
					</div>
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'Types', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-types">{{ data.types }}</div>
					</div>
				</div>
				<div class="wpforms-log-popup-flex wpforms-log-popup-flex-column-4">
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'Log ID', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-id">{{ data.ID }}</div>
					</div>
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'Form ID', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-form-id">
							<# if ( data.form_id ) { #>
							<a href="{{ data.form_url }}">
								<# } #>
								{{ data.form_id }}
								<# if ( data.form_id ) { #>
							</a>
							<# } #>
						</div>
					</div>
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'Entry ID', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-entry-id">
							<# if ( data.entry_id ) { #>
							<a href="{{ data.entry_url }}">
								<# } #>
								{{ data.entry_id }}
								<# if ( data.entry_id ) { #>
							</a>
							<# } #>
						</div>
					</div>
					<div>
						<div class="wpforms-log-popup-label"><?php esc_html_e( 'User ID', 'wpforms-lite' ); ?></div>
						<div class="wpforms-log-popup-user-id">
							<# if ( data.user_id ) { #>
							<a href="{{ data.user_url }}">
								<# } #>
								{{ data.user_id }}
								<# if ( data.user_id ) { #>
							</a>
							<# } #>
						</div>
					</div>
				</div>
			</div>
		</script>
		<?php
	}

	/**
	 * Display list table page.
	 *
	 * @since 1.6.3
	 */
	public function display_page() {

		$this->prepare_column_headers();
		$this->prepare_items();
		echo '<div class="wpforms-list-table wpforms-list-table--logs">';
		echo '<form id="' . esc_attr( $this->_args['plural'] ) . '-filter" method="get">';
		$this->header();
		$this->display();
		echo '</form>';
		echo '</div>';
	}

	/**
	 * Check if the database table exist.
	 *
	 * @since 1.6.4
	 *
	 * @return bool
	 */
	public function table_exists() {

		return $this->repository->table_exists();
	}

	/**
	 * Get total logs.
	 *
	 * @since 1.6.3
	 *
	 * @return int
	 */
	public function get_total() {

		return $this->repository->get_total();
	}

	/**
	 * Gets the screen per_page option name.
	 *
	 * @since 1.7.5
	 *
	 * @return string
	 */
	private function get_per_page_option_name() {

		return str_replace( '-', '_', $this->screen->id ) . '_per_page';
	}
}
