<?php

namespace WPForms\Admin\Forms;

/**
 * Search Forms feature.
 *
 * @since 1.7.2
 */
class Search {

	/**
	 * Current search term.
	 *
	 * @since 1.7.2
	 *
	 * @var string
	 */
	private $term;

	/**
	 *  Current search term escaped.
	 *
	 * @since 1.7.2
	 *
	 * @var string
	 */
	private $term_escaped;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.7.2
	 *
	 * @return bool
	 */
	private function allow_load() {

		// Load only on the `All Forms` admin page and only if the search should be performed.
		return wpforms_is_admin_page( 'overview' ) && $this->is_search();
	}

	/**
	 * Initialize class.
	 *
	 * @since 1.7.2
	 */
	public function init() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$this->term = isset( $_GET['search']['term'] ) ? sanitize_text_field( wp_unslash( $_GET['search']['term'] ) ) : '';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$this->term_escaped = isset( $_GET['search']['term'] ) ? esc_html( wp_unslash( $_GET['search']['term'] ) ) : '';

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.2
	 */
	private function hooks() {

		// Use filter to add the search term to the get forms arguments.
		add_filter( 'wpforms_get_multiple_forms_args', [ $this, 'get_forms_args' ] );

		// Encapsulate search into posts_where.
		add_action( 'wpforms_form_handler_get_multiple_before_get_posts', [ $this, 'before_get_posts' ] );
		add_action( 'wpforms_form_handler_get_multiple_after_get_posts', [ $this, 'after_get_posts' ], 10, 2 );
	}

	/**
	 * Determine whether a search is performing.
	 *
	 * @since 1.7.2
	 *
	 * @return bool
	 */
	private function is_search() {

		return ! wpforms_is_empty_string( $this->term_escaped );
	}

	/**
	 * Count search results.
	 *
	 * @since 1.7.2
	 * @deprecated 1.7.5
	 *
	 * @param array $count Number of forms in different views.
	 * @param array $args  Get forms arguments.
	 *
	 * @return array
	 */
	public function update_count( $count, $args ) {

		_deprecated_function( __METHOD__, '1.7.5 of the WPForms plugin', "wpforms()->get( 'forms_views' )->update_count()" );

		return wpforms()->get( 'forms_views' )->update_count();
	}

	/**
	 * Pass the search term to the arguments array.
	 *
	 * @since 1.7.2
	 *
	 * @param array $args Get posts arguments.
	 *
	 * @return array
	 */
	public function get_forms_args( $args ) {

		$args['search']['term']         = $this->term;
		$args['search']['term_escaped'] = $this->term_escaped;

		return $args;
	}

	/**
	 * Before get_posts() call routine.
	 *
	 * @since 1.7.2
	 *
	 * @param array $args Arguments of the `get_posts()`.
	 */
	public function before_get_posts( $args ) {

		// The `posts_where` hook is very general and has broad usage across the WP core and tons of plugins.
		// Therefore, in order to do not break something,
		// we should add this hook right before the call of `get_posts()` inside \WPForms_Form_Handler::get_multiple().
		add_filter( 'posts_where', [ $this, 'search_by_term_where' ], 10, 2 );
	}

	/**
	 * After get_posts() call routine.
	 *
	 * @since 1.7.2
	 *
	 * @param array $args  Arguments of the get_posts().
	 * @param array $forms Forms data. Result of getting multiple forms.
	 */
	public function after_get_posts( $args, $forms ) {

		// The `posts_where` hook is very general and has broad usage across the WP core and tons of plugins.
		// Therefore, in order to do not break something,
		// we should remove this hook right after the call of `get_posts()` inside \WPForms_Form_Handler::get_multiple().
		remove_filter( 'posts_where', [ $this, 'search_by_term_where' ] );
	}

	/**
	 * Modify the WHERE clause of the SQL query in order to search forms by given term.
	 *
	 * @since 1.7.2
	 *
	 * @param string    $where    WHERE clause.
	 * @param \WP_Query $wp_query The WP_Query instance.
	 *
	 * @return string
	 */
	public function search_by_term_where( $where, $wp_query ) {

		global $wpdb;

		// When user types only HTML tag (<section> for example), the sanitized term we will be empty.
		// In this case, it's better to return an empty result set than all the forms. It's not the same as the empty search term.
		if ( wpforms_is_empty_string( $this->term ) && ! wpforms_is_empty_string( $this->term_escaped ) ) {
			$where .= ' AND 1<>1';
		}

		if ( wpforms_is_empty_string( $this->term ) ) {
			return $where;
		}

		// Prepare the WHERE clause to search form title and description.
		$where .= $wpdb->prepare(
			" AND (
				{$wpdb->posts}.post_title LIKE %s OR
				{$wpdb->posts}.post_excerpt LIKE %s
			)",
			'%' . $wpdb->esc_like( esc_html( $this->term ) ) . '%',
			'%' . $wpdb->esc_like( $this->term ) . '%'
		);

		return $where;
	}

	/**
	 * Forms search markup.
	 *
	 * @since 1.7.2
	 *
	 * @param string $text     The 'submit' button label.
	 * @param string $input_id ID attribute value for the search input field.
	 */
	public function search_box( $text, $input_id ) {

		$search_term = wpforms_is_empty_string( $this->term ) ? $this->term_escaped : $this->term;

		// Display search reset block.
		$this->search_reset_block( $search_term );

		// Display search box.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'admin/forms/search-box',
			[
				'term_input_id' => $input_id . '-term',
				'text'          => $text,
				'search_term'   => $search_term,
			],
			true
		);
	}

	/**
	 * Forms search reset block.
	 *
	 * @since 1.7.2
	 *
	 * @param string $search_term Current search term.
	 */
	private function search_reset_block( $search_term ) {

		if ( wpforms_is_empty_string( $search_term ) ) {
			return;
		}

		$views = wpforms()->get( 'forms_views' );
		$count = $views->get_count();
		$view  = $views->get_current_view();

		$count['all'] = ! empty( $count['all'] ) ? $count['all'] : 0;

		$message = sprintf(
			wp_kses( /* translators: %1$d - number of forms found, %2$s - search term. */
				_n(
					'Found <strong>%1$d form</strong> containing <em>"%2$s"</em>',
					'Found <strong>%1$d forms</strong> containing <em>"%2$s"</em>',
					(int) $count['all'],
					'wpforms-lite'
				),
				[
					'strong' => [],
					'em'     => [],
				]
			),
			(int) $count['all'],
			esc_html( $search_term )
		);

		/**
		 * Filters the message in the search reset block.
		 *
		 * @since 1.7.3
		 *
		 * @param string $message     Message text.
		 * @param string $search_term Search term.
		 * @param array  $count       Count forms in different views.
		 * @param string $view        Current view.
		 */
		$message = apply_filters( 'wpforms_admin_forms_search_search_reset_block_message', $message, $search_term, $count, $view );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'admin/forms/search-reset',
			[
				'message' => $message,
			],
			true
		);
	}
}
