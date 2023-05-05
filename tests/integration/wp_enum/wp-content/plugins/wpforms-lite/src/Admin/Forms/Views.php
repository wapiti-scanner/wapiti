<?php

namespace WPForms\Admin\Forms;

use WP_Post;

/**
 * List table views.
 *
 * @since 1.7.3
 */
class Views {

	/**
	 * Current view slug.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $current_view;

	/**
	 * Views settings.
	 *
	 * @since 1.7.3
	 *
	 * @var array
	 */
	private $views;

	/**
	 * Count forms in different views.
	 *
	 * @since 1.7.3
	 *
	 * @var array
	 */
	private $count;

	/**
	 * Base URL.
	 *
	 * @since 1.7.3
	 *
	 * @var string
	 */
	private $base_url;

	/**
	 * Views configuration.
	 *
	 * @since 1.7.3
	 */
	private function configuration() {

		if ( ! empty( $this->views ) ) {
			return;
		}

		// Define views.
		$views = [
			'all'   => [
				'title'         => __( 'All', 'wpforms-lite' ),
				'get_var'       => '',
				'get_var_value' => '',
			],
			'trash' => [
				'title'         => __( 'Trash', 'wpforms-lite' ),
				'get_var'       => 'status',
				'get_var_value' => 'trash',
			],
		];

		// phpcs:disable WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity

		/**
		 * Filters configuration of the Forms Overview table views.
		 *
		 * @since 1.7.3
		 *
		 * @param array $views {
		 *    Views array.
		 *
		 *    @param array $view {
		 *        Each view is the array with three elements:
		 *
		 *        @param string $title         View title.
		 *        @param string $get_var       URL query variable name.
		 *        @param string $get_var_value URL query variable value.
		 *    }
		 *    ...
		 * }
		 */
		$this->views = apply_filters( 'wpforms_admin_forms_views_configuration', $views );

		// phpcs:enable WPForms.Comments.ParamTagHooks.InvalidParamTagsQuantity
	}

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

		$this->configuration();
		$this->update_current_view();
		$this->update_base_url();
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		add_filter( 'wpforms_overview_table_update_count', [ $this, 'update_count' ], 10, 2 );
		add_filter( 'wpforms_overview_table_update_count_all', [ $this, 'update_count' ], 10, 2 );
		add_filter( 'wpforms_overview_table_prepare_items_args', [ $this, 'prepare_items_trash' ], 100 );
		add_filter( 'wpforms_overview_row_actions', [ $this, 'row_actions_all' ], 9, 2 );
		add_filter( 'wpforms_overview_row_actions', [ $this, 'row_actions_trash' ], PHP_INT_MAX, 2 );
		add_filter( 'wpforms_admin_forms_search_search_reset_block_message', [ $this, 'search_reset_message' ], 10, 4 );
	}

	/**
	 * Determine and save current view slug.
	 *
	 * @since 1.7.3
	 */
	private function update_current_view() {

		if ( ! is_array( $this->views ) ) {
			return;
		}

		$this->current_view = 'all';

		foreach ( $this->views as $slug => $view ) {

			if (
				// phpcs:disable WordPress.Security.NonceVerification.Recommended
				isset( $_GET[ $view['get_var'] ] ) &&
				$view['get_var_value'] === sanitize_key( $_GET[ $view['get_var'] ] )
				// phpcs:enable WordPress.Security.NonceVerification.Recommended
			) {
				$this->current_view = $slug;

				return;
			}
		}
	}

	/**
	 * Update Base URL.
	 *
	 * @since 1.7.3
	 */
	private function update_base_url() {

		if ( ! is_array( $this->views ) ) {
			return;
		}

		$get_vars = wp_list_pluck( $this->views, 'get_var' );
		$get_vars = array_merge(
			$get_vars,
			[
				'paged',
				'trashed',
				'restored',
				'deleted',
				'duplicated',
			]
		);

		$this->base_url = remove_query_arg( $get_vars );
	}

	/**
	 * Get current view slug.
	 *
	 * @since 1.7.3
	 *
	 * @return string
	 */
	public function get_current_view() {

		return $this->current_view;
	}

	/**
	 * Get base URL.
	 *
	 * @since 1.7.5
	 *
	 * @return string
	 */
	public function get_base_url() {

		return $this->base_url;
	}

	/**
	 * Get view configuration by slug.
	 *
	 * @since 1.7.5
	 *
	 * @param string $slug View slug.
	 *
	 * @return array
	 */
	public function get_view_by_slug( $slug ) {

		return isset( $this->views[ $slug ] ) ? $this->views[ $slug ] : [];
	}

	/**
	 * Update count.
	 *
	 * @since 1.7.3
	 *
	 * @param array $count Number of forms in different views.
	 * @param array $args  Get forms arguments.
	 *
	 * @return array
	 */
	public function update_count( $count, $args ) {

		// Count forms in Trash.
		// We should perform the search of the trashed forms without paging and then count the results.
		$args = array_merge(
			$args,
			[
				'nopaging'               => true,
				'no_found_rows'          => true,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
				'fields'                 => 'ids',
				'post_status'            => 'trash',
			]
		);

		$forms          = wpforms()->get( 'form' )->get( '', $args );
		$count['trash'] = is_array( $forms ) ? count( $forms ) : 0;

		// Count all published forms.
		$args['post_status'] = 'publish';
		$forms               = wpforms()->get( 'form' )->get( '', $args );
		$count['all']        = is_array( $forms ) ? count( $forms ) : 0;

		// Store in class property for further use.
		$this->count = $count;

		return $count;
	}

	/**
	 * Get counts of forms in different views.
	 *
	 * @since 1.7.3
	 *
	 * @return array
	 */
	public function get_count() {

		return $this->count;
	}

	/**
	 * Get forms from Trash when preparing items for list table.
	 *
	 * @since 1.7.3
	 *
	 * @param array $args Get multiple forms arguments.
	 *
	 * @return array
	 */
	public function prepare_items_trash( $args ) {

		// Update arguments of \WPForms_Form_Handler::get_multiple() in order to get forms in Trash.
		if ( $this->current_view === 'trash' ) {
			$args['post_status'] = 'trash';
		}

		return $args;
	}

	/**
	 * Generate views items.
	 *
	 * @since 1.7.3
	 *
	 * @return array
	 */
	public function get_views() {

		if ( ! is_array( $this->views ) ) {
			return [];
		}

		$views = [];

		foreach ( $this->views as $slug => $view ) {

			if (
				$slug === 'trash' &&
				$this->current_view !== 'trash' &&
				empty( $this->count[ $slug ] )
			) {
				continue;
			}

			$views[ $slug ] = $this->get_view_markup( $slug );
		}

		/**
		 * Filters the Forms Overview table views links.
		 *
		 * @since 1.7.3
		 *
		 * @param array $views Views links.
		 * @param array $count Count forms in different views.
		 */
		return apply_filters( 'wpforms_admin_forms_views_get_views', $views, $this->count );
	}

	/**
	 * Generate single view item.
	 *
	 * @since 1.7.3
	 *
	 * @param string $slug View slug.
	 *
	 * @return string
	 */
	private function get_view_markup( $slug ) {

		if ( empty( $this->views[ $slug ] ) ) {
			return '';
		}

		$view = $this->views[ $slug ];

		return sprintf(
			'<a href="%1$s"%2$s>%3$s&nbsp;<span class="count">(%4$d)</span></a>',
			$slug === 'all' ? esc_url( $this->base_url ) : esc_url( add_query_arg( $view['get_var'], $view['get_var_value'], $this->base_url ) ),
			$this->current_view === $slug ? ' class="current"' : '',
			esc_html( $view['title'] ),
			empty( $this->count[ $slug ] ) ? 0 : absint( $this->count[ $slug ] )
		);
	}

	/**
	 * Row actions for view "All".
	 *
	 * @since 1.7.3
	 *
	 * @param array   $row_actions Row actions.
	 * @param WP_Post $form        Form object.
	 *
	 * @return array
	 */
	public function row_actions_all( $row_actions, $form ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh

		if ( $this->current_view !== 'all' ) {
			return $row_actions;
		}

		$row_actions = [];

		// Edit.
		if ( wpforms_current_user_can( 'edit_form_single', $form->ID ) ) {
			$row_actions['edit'] = sprintf(
				'<a href="%s" title="%s">%s</a>',
				esc_url(
					add_query_arg(
						[
							'view'    => 'fields',
							'form_id' => $form->ID,
						],
						admin_url( 'admin.php?page=wpforms-builder' )
					)
				),
				esc_attr__( 'Edit This Form', 'wpforms-lite' ),
				esc_html__( 'Edit', 'wpforms-lite' )
			);
		}

		// Entries.
		if ( wpforms_current_user_can( 'view_entries_form_single', $form->ID ) ) {
			$row_actions['entries'] = sprintf(
				'<a href="%s" title="%s">%s</a>',
				esc_url(
					add_query_arg(
						[
							'view'    => 'list',
							'form_id' => $form->ID,
						],
						admin_url( 'admin.php?page=wpforms-entries' )
					)
				),
				esc_attr__( 'View entries', 'wpforms-lite' ),
				esc_html__( 'Entries', 'wpforms-lite' )
			);
		}

		// Preview.
		if ( wpforms_current_user_can( 'view_form_single', $form->ID ) ) {
			$row_actions['preview_'] = sprintf(
				'<a href="%s" title="%s" target="_blank" rel="noopener noreferrer">%s</a>',
				esc_url( wpforms_get_form_preview_url( $form->ID ) ),
				esc_attr__( 'View preview', 'wpforms-lite' ),
				esc_html__( 'Preview', 'wpforms-lite' )
			);
		}

		// Duplicate.
		if ( wpforms_current_user_can( 'create_forms' ) && wpforms_current_user_can( 'view_form_single', $form->ID ) ) {
			$row_actions['duplicate'] = sprintf(
				'<a href="%s" title="%s">%s</a>',
				esc_url(
					wp_nonce_url(
						add_query_arg(
							[
								'action'  => 'duplicate',
								'form_id' => $form->ID,
							],
							$this->base_url
						),
						'wpforms_duplicate_form_nonce'
					)
				),
				esc_attr__( 'Duplicate this form', 'wpforms-lite' ),
				esc_html__( 'Duplicate', 'wpforms-lite' )
			);
		}

		// Trash.
		if ( wpforms_current_user_can( 'delete_form_single', $form->ID ) ) {
			$row_actions['trash'] = sprintf(
				'<a href="%s" title="%s">%s</a>',
				esc_url(
					wp_nonce_url(
						add_query_arg(
							[
								'action'  => 'trash',
								'form_id' => $form->ID,
							],
							$this->base_url
						),
						'wpforms_trash_form_nonce'
					)
				),
				esc_attr__( 'Move this form to trash', 'wpforms-lite' ),
				esc_html__( 'Trash', 'wpforms-lite' )
			);
		}

		return $row_actions;
	}

	/**
	 * Row actions for view "Trash".
	 *
	 * @since 1.7.3
	 *
	 * @param array   $row_actions Row actions.
	 * @param WP_Post $form        Form object.
	 *
	 * @return array
	 */
	public function row_actions_trash( $row_actions, $form ) {

		if (
			$this->current_view !== 'trash' ||
			! wpforms_current_user_can( 'delete_form_single', $form->ID )
		) {
			return $row_actions;
		}

		$row_actions = [];

		// Restore form.
		$row_actions['restore'] = sprintf(
			'<a href="%s" title="%s">%s</a>',
			esc_url(
				wp_nonce_url(
					add_query_arg(
						[
							'action'  => 'restore',
							'form_id' => $form->ID,
							'status'  => 'trash',
						],
						$this->base_url
					),
					'wpforms_restore_form_nonce'
				)
			),
			esc_attr__( 'Restore this form', 'wpforms-lite' ),
			esc_html__( 'Restore', 'wpforms-lite' )
		);

		// Delete permanently.
		$row_actions['delete'] = sprintf(
			'<a href="%s" title="%s">%s</a>',
			esc_url(
				wp_nonce_url(
					add_query_arg(
						[
							'action'  => 'delete',
							'form_id' => $form->ID,
							'status'  => 'trash',
						],
						$this->base_url
					),
					'wpforms_delete_form_nonce'
				)
			),
			esc_attr__( 'Delete this form permanently', 'wpforms-lite' ),
			esc_html__( 'Delete Permanently', 'wpforms-lite' )
		);

		return $row_actions;
	}

	/**
	 * Search reset message.
	 *
	 * @since 1.7.3
	 *
	 * @param string $message      Search reset block message.
	 * @param string $search_term  Search term.
	 * @param array  $count        Count forms in different views.
	 * @param string $current_view Current view.
	 *
	 * @return string
	 */
	public function search_reset_message( $message, $search_term, $count, $current_view ) {

		if ( $current_view !== 'trash' ) {
			return $message;
		}

		$count['trash'] = ! empty( $count['trash'] ) ? $count['trash'] : 0;

		return sprintf(
			wp_kses( /* translators: %1$d - number of forms found in the trash, %2$s - search term. */
				_n(
					'Found <strong>%1$d form</strong> in <em>the trash</em> containing <em>"%2$s"</em>',
					'Found <strong>%1$d forms</strong> in <em>the trash</em> containing <em>"%2$s"</em>',
					(int) $count['trash'],
					'wpforms-lite'
				),
				[
					'strong' => [],
					'em'     => [],
				]
			),
			(int) $count['trash'],
			esc_html( $search_term )
		);
	}

	/**
	 * Extra controls to be displayed between bulk actions and pagination.
	 *
	 * @since 1.7.3
	 *
	 * @param string $which The location of the table navigation: 'top' or 'bottom'.
	 */
	public function extra_tablenav( $which ) {

		if ( ! wpforms_current_user_can( 'delete_form_single' ) ) {
			return;
		}

		if ( $this->current_view !== 'trash' ) {
			return;
		}

		// Preserve current view after applying bulk action.
		echo '<input type="hidden" name="status" value="trash">';

		// Display Empty Trash button.
		printf(
			'<a href="%1$s" class="button delete-all">%2$s</a>',
			esc_url(
				wp_nonce_url(
					add_query_arg(
						[
							'action'  => 'empty_trash',
							'form_id' => 1, // Technically, `empty_trash` is one of the bulk actions, therefore we need to provide fake form_id to proceed.
							'status'  => 'trash',
						],
						$this->base_url
					),
					'wpforms_empty_trash_form_nonce'
				)
			),
			esc_html__( 'Empty Trash', 'wpforms-lite' )
		);
	}
}
