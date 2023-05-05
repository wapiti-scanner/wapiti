<?php

namespace WPForms\Admin\Forms;

use WP_Post;
use WPForms_Form_Handler;
use WPForms_Overview_Table;

/**
 * Tags on All Forms page.
 *
 * @since 1.7.5
 */
class Tags {

	/**
	 * Current tags filter.
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	private $tags_filter;

	/**
	 * Current view slug.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	private $current_view;

	/**
	 * Base URL.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	private $base_url;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.7.5
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
	 * @since 1.7.5
	 */
	public function init() {

		// In case of AJAX call we need to initialize base URL only.
		if ( wp_doing_ajax() ) {
			$this->base_url = admin_url( 'admin.php?page=wpforms-overview' );
		}

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->update_view_vars();
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		add_action( 'init', [ $this, 'update_tags_filter' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_action( 'wpforms_admin_overview_before_rows', [ $this, 'bulk_edit_tags' ] );
		add_filter( 'wpforms_get_multiple_forms_args', [ $this, 'get_forms_args' ] );
		add_filter( 'wpforms_admin_forms_bulk_actions_get_dropdown_items', [ $this, 'add_bulk_action' ], 10, 2 );
		add_filter( 'wpforms_overview_table_columns', [ $this, 'filter_columns' ] );
	}

	/**
	 * Init view-related variables.
	 *
	 * @since 1.7.5
	 */
	private function update_view_vars() {

		$views_object       = wpforms()->get( 'forms_views' );
		$this->current_view = $views_object->get_current_view();
		$view_config        = $views_object->get_view_by_slug( $this->current_view );
		$this->base_url     = remove_query_arg(
			[ 'tags', 'search', 'action', 'action2', '_wpnonce', 'form_id', 'paged', '_wp_http_referer' ],
			$views_object->get_base_url()
		);

		// Base URL should contain variable according to the current view.
		if (
			isset( $view_config['get_var'], $view_config['get_var_value'] ) && $this->current_view !== 'all'
		) {
			$this->base_url = add_query_arg( $view_config['get_var'], $view_config['get_var_value'], $this->base_url );
		}

		// Base URL fallback.
		$this->base_url = empty( $this->base_url ) ? admin_url( 'admin.php?page=wpforms-overview' ) : $this->base_url;
	}

	/**
	 * Update tags filter value.
	 *
	 * @since 1.7.5
	 */
	public function update_tags_filter() {

		// Do not need to update this property while doing AJAX.
		if ( wp_doing_ajax() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$tags        = isset( $_GET['tags'] ) ? sanitize_text_field( wp_unslash( rawurldecode( $_GET['tags'] ) ) ) : '';
		$tags_slugs  = explode( ',', $tags );
		$tags_filter = array_filter(
			self::get_all_tags_choices(),
			static function( $tag ) use ( $tags_slugs ) {

				return in_array( trim( rawurldecode( $tag['slug'] ) ), $tags_slugs, true );
			}
		);

		$this->tags_filter = array_map( 'absint', wp_list_pluck( $tags_filter, 'value' ) );
	}

	/**
	 * Enqueue assets.
	 *
	 * @since 1.7.5
	 */
	public function enqueues() {

		wp_enqueue_script(
			'wpforms-admin-forms-overview-choicesjs',
			WPFORMS_PLUGIN_URL . 'assets/lib/choices.min.js',
			[],
			'9.0.1',
			true
		);

		wp_localize_script(
			'wpforms-admin-forms-overview-choicesjs',
			'wpforms_admin_forms_overview',
			[
				'choicesjs_config' => self::get_choicesjs_config(),
				'edit_tags_form'   => $this->get_column_tags_form(),
				'all_tags_choices' => self::get_all_tags_choices(),
				'strings'          => $this->get_localize_strings(),
			]
		);
	}

	/**
	 * Get Choices.js configuration.
	 *
	 * @since 1.7.5
	 */
	public static function get_choicesjs_config() {

		return [
			'removeItemButton'  => true,
			'shouldSort'        => false,
			'loadingText'       => esc_html__( 'Loading...', 'wpforms-lite' ),
			'noResultsText'     => esc_html__( 'No results found', 'wpforms-lite' ),
			'noChoicesText'     => esc_html__( 'No tags to choose from', 'wpforms-lite' ),
			'itemSelectText'    => '',
			'searchEnabled'     => true,
			'searchChoices'     => true,
			'searchFloor'       => 1,
			'searchResultLimit' => 100,
			'searchFields'      => [ 'label' ],
			// These `fuseOptions` options enable the search of chars not only from the beginning of the tags.
			'fuseOptions'       => [
				'threshold' => 0.1,
				'distance'  => 1000,
				'location'  => 2,
			],
		];
	}

	/**
	 * Get all tags (terms) as items for Choices.js.
	 *
	 * @since 1.7.5
	 *
	 * @return array
	 */
	public static function get_all_tags_choices() {

		static $choices = null;

		if ( is_array( $choices ) ) {
			return $choices;
		}

		$choices = [];
		$tags    = get_terms(
			[
				'taxonomy'   => WPForms_Form_Handler::TAGS_TAXONOMY,
				'hide_empty' => false,
			]
		);

		foreach ( $tags as $tag ) {
			$choices[] = [
				'value' => (string) $tag->term_id,
				'slug'  => $tag->slug,
				'label' => sanitize_term_field( 'name', $tag->name, $tag->term_id, WPForms_Form_Handler::TAGS_TAXONOMY, 'display' ),
				'count' => (int) $tag->count,
			];
		}

		return $choices;
	}

	/**
	 * Determine if the Tags column is hidden.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function is_tags_column_hidden() {

		$overview_table = WPForms_Overview_Table::get_instance();
		$columns        = $overview_table->__call( 'get_column_info', [] );

		return isset( $columns[1] ) && in_array( 'tags', $columns[1], true );
	}

	/**
	 * Get localize strings.
	 *
	 * @since 1.7.5
	 */
	private function get_localize_strings() {

		return [
			'nonce'                    => wp_create_nonce( 'wpforms-admin-forms-overview-nonce' ),
			'is_tags_column_hidden'    => $this->is_tags_column_hidden(),
			'base_url'                 => admin_url( 'admin.php?' . wp_parse_url( $this->base_url, PHP_URL_QUERY ) ),
			'add_new_tag'              => esc_html__( 'Press Enter or "," key to add new tag', 'wpforms-lite' ),
			'error'                    => esc_html__( 'Something wrong. Please try again later.', 'wpforms-lite' ),
			'all_tags'                 => esc_html__( 'All Tags', 'wpforms-lite' ),
			'bulk_edit_one_form'       => wp_kses(
				__( '<strong>1 form</strong> selected for Bulk Edit.', 'wpforms-lite' ),
				[ 'strong' => [] ]
			),
			'bulk_edit_n_forms'        => wp_kses( /* translators: %d - Number of forms selected for Bulk Edit. */
				__( '<strong>%d forms</strong> selected for Bulk Edit.', 'wpforms-lite' ),
				[ 'strong' => [] ]
			),
			'manage_tags_title'        => esc_html__( 'Manage Tags', 'wpforms-lite' ),
			'manage_tags_desc'         => esc_html__( 'Delete tags that you\'re no longer using. Deleting a tag will remove it from a form, but will not delete the form itself.', 'wpforms-lite' ),
			'manage_tags_save'         => esc_html__( 'Delete Tags', 'wpforms-lite' ),
			'manage_tags_one_tag'      => wp_kses(
				__( 'You have <strong>1 tag</strong> selected for deletion.', 'wpforms-lite' ),
				[ 'strong' => [] ]
			),
			'manage_tags_n_tags'       => wp_kses( /* translators: %d - Number of forms selected for Bulk Edit. */
				__( 'You have <strong>%d tags</strong> selected for deletion.', 'wpforms-lite' ),
				[ 'strong' => [] ]
			),
			'manage_tags_no_tags'      => wp_kses(
				__( 'There are no tags to delete.<br>Please create at least one by adding it to any form.', 'wpforms-lite' ),
				[ 'br' => [] ]
			),
			'manage_tags_one_deleted'  => esc_html__( '1 tag was successfully deleted.', 'wpforms-lite' ),
			/* translators: %d - Number of deleted tags. */
			'manage_tags_n_deleted'    => esc_html__( '%d tags were successfully deleted.', 'wpforms-lite' ),
			'manage_tags_result_title' => esc_html__( 'Almost done!', 'wpforms-lite' ),
			'manage_tags_result_text'  => esc_html__( 'In order to update the tags in the forms list, please refresh the page.', 'wpforms-lite' ),
			'manage_tags_btn_refresh'  => esc_html__( 'Refresh', 'wpforms-lite' ),
		];
	}

	/**
	 * Determine if tags are editable.
	 *
	 * @since 1.7.5
	 *
	 * @param int|null $form_id Form ID.
	 *
	 * @return bool
	 */
	private function is_editable( $form_id = null ) {

		if ( $this->current_view === 'trash' ) {
			return false;
		}

		if ( ! empty( $form_id ) && ! wpforms_current_user_can( 'edit_form_single', $form_id ) ) {
			return false;
		}

		if ( empty( $form_id ) && ! wpforms_current_user_can( 'edit_forms' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Generate Tags column markup.
	 *
	 * @since 1.7.5
	 *
	 * @param WP_Post $form Form.
	 *
	 * @return string
	 */
	public function column_tags( $form ) {

		$terms = get_the_terms( $form->ID, WPForms_Form_Handler::TAGS_TAXONOMY );
		$data  = $this->get_tags_data( $terms );

		return $this->get_column_tags_links( $data['tags_links'], $data['tags_ids'], $form->ID ) . $this->get_column_tags_form( $data['tags_options'] );
	}

	/**
	 * Generate tags data.
	 *
	 * @since 1.7.5
	 *
	 * @param array $terms Tags terms.
	 *
	 * @return array
	 */
	public function get_tags_data( $terms ) {

		if ( ! is_array( $terms ) ) {

			$taxonomy_object = get_taxonomy( WPForms_Form_Handler::TAGS_TAXONOMY );

			return [
				'tags_links'   => sprintf(
					'<span aria-hidden="true">&#8212;</span><span class="screen-reader-text">%s</span>',
					esc_html( isset( $taxonomy_object->labels->no_terms ) ? $taxonomy_object->labels->no_terms : '—' )
				),
				'tags_ids'     => '',
				'tags_options' => '',
			];
		}

		$tags_links   = [];
		$tags_ids     = [];
		$tags_options = [];

		$terms = empty( $terms ) ? [] : (array) $terms;

		foreach ( $terms as $tag ) {

			$filter_url = add_query_arg(
				'tags',
				rawurlencode( $tag->slug ),
				$this->base_url
			);

			$tags_links[] = sprintf(
				'<a href="%1$s">%2$s</a>',
				esc_url( $filter_url ),
				esc_html( $tag->name )
			);

			$tags_ids[] = $tag->term_id;

			$tags_options[] = sprintf(
				'<option value="%1$s" selected>%2$s</option>',
				esc_attr( $tag->term_id ),
				esc_html( $tag->name )
			);
		}

		return [
			/* translators: Used between list items, there is a space after the comma. */
			'tags_links'   => implode( __( ', ', 'wpforms-lite' ), $tags_links ),
			'tags_ids'     => implode( ',', array_filter( $tags_ids ) ),
			'tags_options' => implode( '', $tags_options ),
		];
	}

	/**
	 * Get form tags links list markup.
	 *
	 * @since 1.7.5
	 *
	 * @param string $tags_links Tags links.
	 * @param string $tags_ids   Tags IDs.
	 * @param int    $form_id    Form ID.
	 *
	 * @return string
	 */
	private function get_column_tags_links( $tags_links = '', $tags_ids = '', $form_id = 0 ) {

		$edit_link = '';

		if ( $this->is_editable( $form_id ) ) {
			$edit_link = sprintf(
				'<a href="#" class="wpforms-column-tags-edit">%s</a>',
				esc_html__( 'Edit', 'wpforms-lite' )
			);
		}

		return sprintf(
			'<div class="wpforms-column-tags-links" data-form-id="%1$d" data-is-editable="%2$s" data-tags="%3$s">
				<div class="wpforms-column-tags-links-list">%4$s</div>
				%5$s
			</div>',
			absint( $form_id ),
			$this->is_editable( $form_id ) ? '1' : '0',
			esc_attr( $tags_ids ),
			$tags_links,
			$edit_link
		);
	}

	/**
	 * Get edit tags form markup in the Tags column.
	 *
	 * @since 1.7.5
	 *
	 * @param string $tags_options Tags options.
	 *
	 * @return string
	 */
	private function get_column_tags_form( $tags_options = '' ) {

		return sprintf(
			'<div class="wpforms-column-tags-form wpforms-hidden">
				<select multiple>%1$s</select>
				<i class="dashicons dashicons-dismiss wpforms-column-tags-edit-cancel" title="%2$s"></i>
				<i class="dashicons dashicons-yes-alt wpforms-column-tags-edit-save" title="%3$s"></i>
				<i class="wpforms-spinner spinner wpforms-hidden"></i>
			</div>',
			$tags_options,
			esc_attr__( 'Cancel', 'wpforms-lite' ),
			esc_attr__( 'Save changes', 'wpforms-lite' )
		);
	}

	/**
	 * Extra controls to be displayed between bulk actions and pagination.
	 *
	 * @since 1.7.5
	 *
	 * @param string                 $which          The location of the table navigation: 'top' or 'bottom'.
	 * @param WPForms_Overview_Table $overview_table Instance of the WPForms_Overview_Table class.
	 */
	public function extra_tablenav( $which, $overview_table ) {

		if ( $this->current_view === 'trash' ) {
			return;
		}

		$all_tags         = self::get_all_tags_choices();
		$is_column_hidden = $this->is_tags_column_hidden();
		$is_hidden        = $is_column_hidden || empty( $all_tags );
		$tags_options     = '';

		if ( $this->is_filtered() ) {
			$tags = get_terms(
				[
					'taxonomy'   => WPForms_Form_Handler::TAGS_TAXONOMY,
					'hide_empty' => false,
					'include'    => $this->tags_filter,
				]
			);

			foreach ( $tags as $tag ) {
				$tags_options .= sprintf(
					'<option value="%1$s" selected>%2$s</option>',
					esc_attr( $tag->term_id ),
					esc_html( $tag->name )
				);
			}
		}

		printf(
			'<div class="wpforms-tags-filter %1$s">
				<select multiple size="1" data-tags-filter="1">
					<option placeholder>%2$s</option>
					%3$s
				</select>
				<button type="button" class="button">%4$s</button>
			</div>
			<button type="button" class="button wpforms-manage-tags %1$s">%5$s</button>',
			esc_attr( $is_hidden ? 'wpforms-hidden' : '' ),
			esc_html( empty( $tags_options ) ? __( 'All Tags', 'wpforms-lite' ) : '' ),
			wp_kses(
				$tags_options,
				[
					'option' => [
						'value'    => [],
						'selected' => [],
					],
				]
			),
			esc_attr__( 'Filter', 'wpforms-lite' ),
			esc_attr__( 'Manage Tags', 'wpforms-lite' )
		);
	}

	/**
	 * Render and display Bulk Edit Tags form.
	 *
	 * @since 1.7.5
	 *
	 * @param WPForms_Overview_Table $list_table Overview lit table object.
	 */
	public function bulk_edit_tags( $list_table ) {

		$columns = $list_table->get_columns();

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'admin/forms/bulk-edit-tags',
			[
				'columns' => count( $columns ),
			],
			true
		);
	}

	/**
	 * Determine whether a filtering is performing.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function is_filtered() {

		return ! empty( $this->tags_filter );
	}

	/**
	 * Pass the tags to the arguments array.
	 *
	 * @since 1.7.5
	 *
	 * @param array $args Get posts arguments.
	 *
	 * @return array
	 */
	public function get_forms_args( $args ) {

		if ( $args['post_status'] === 'trash' || ! $this->is_filtered() ) {
			return $args;
		}

		// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_tax_query
		$args['tax_query'] = [
			[
				'taxonomy' => WPForms_Form_Handler::TAGS_TAXONOMY,
				'field'    => 'term_id',
				'terms'    => $this->tags_filter,
			],
		];

		return $args;
	}

	/**
	 * Add item to Bulk Actions dropdown.
	 *
	 * @since 1.7.5
	 *
	 * @param array $items Dropdown items.
	 *
	 * @return array
	 */
	public function add_bulk_action( $items ) {

		if ( $this->is_editable() ) {
			$items['edit_tags'] = esc_html__( 'Edit Tags', 'wpforms-lite' );
		}

		return $items;
	}

	/**
	 * Filter list table columns.
	 *
	 * @since 1.7.5
	 *
	 * @param string[] $columns Array of columns.
	 *
	 * @return array
	 */
	public function filter_columns( $columns ) {

		if ( $this->current_view === 'trash' ) {
			unset( $columns['tags'] );
		}

		return $columns;
	}
}
