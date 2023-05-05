<?php

namespace WPForms\Admin;

use WP_Post;

/**
 * Embed Form in a Page wizard.
 *
 * @since 1.6.2
 */
class FormEmbedWizard {

	/**
	 * Max search results count of 'Select Page' dropdown.
	 *
	 * @since 1.7.9
	 *
	 * @var int
	 */
	const MAX_SEARCH_RESULTS_DROPDOWN_PAGES_COUNT = 20;

	/**
	 * Post statuses of pages in 'Select Page' dropdown.
	 *
	 * @since 1.7.9
	 *
	 * @var string[]
	 */
	const POST_STATUSES_OF_DROPDOWN_PAGES = [ 'publish', 'pending' ];

	/**
	 * Initialize class.
	 *
	 * @since 1.6.2
	 */
	public function init() {

		// Form Embed Wizard should load only in the Form Builder and on the Edit/Add Page screen.
		if (
			! wpforms_is_admin_page( 'builder' ) &&
			! wp_doing_ajax() &&
			! $this->is_form_embed_page()
		) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.6.2
	 * @since 1.7.9 Add hook for searching pages in embed wizard via AJAX.
	 */
	public function hooks() {

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_action( 'admin_footer', [ $this, 'output' ] );
		add_filter( 'default_title', [ $this, 'embed_page_title' ], 10, 2 );
		add_filter( 'default_content', [ $this, 'embed_page_content' ], 10, 2 );
		add_action( 'wp_ajax_wpforms_admin_form_embed_wizard_embed_page_url', [ $this, 'get_embed_page_url_ajax' ] );
		add_action( 'wp_ajax_wpforms_admin_form_embed_wizard_search_pages_choicesjs', [ $this, 'get_search_result_pages_ajax' ] );
	}

	/**
	 * Enqueue assets.
	 *
	 * @since 1.6.2
	 * @since 1.7.9 Add 'underscore' as dependency.
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		if ( $this->is_form_embed_page() && $this->get_meta() && ! $this->is_challenge_active() ) {

			wp_enqueue_style(
				'wpforms-admin-form-embed-wizard',
				WPFORMS_PLUGIN_URL . "assets/css/form-embed-wizard{$min}.css",
				[],
				WPFORMS_VERSION
			);

			wp_enqueue_style(
				'tooltipster',
				WPFORMS_PLUGIN_URL . 'assets/lib/jquery.tooltipster/jquery.tooltipster.min.css',
				null,
				'4.2.6'
			);

			wp_enqueue_script(
				'tooltipster',
				WPFORMS_PLUGIN_URL . 'assets/lib/jquery.tooltipster/jquery.tooltipster.min.js',
				[ 'jquery' ],
				'4.2.6',
				true
			);
		}

		wp_enqueue_script(
			'wpforms-admin-form-embed-wizard',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/form-embed-wizard{$min}.js",
			[ 'jquery', 'underscore' ],
			WPFORMS_VERSION
		);

		wp_localize_script(
			'wpforms-admin-form-embed-wizard',
			'wpforms_admin_form_embed_wizard',
			[
				'nonce'        => wp_create_nonce( 'wpforms_admin_form_embed_wizard_nonce' ),
				'is_edit_page' => (int) $this->is_form_embed_page( 'edit' ),
				'video_url'    => esc_url(
					sprintf(
						'https://youtube.com/embed/%s?rel=0&showinfo=0',
						wpforms_is_gutenberg_active() ? '_29nTiDvmLw' : 'IxGVz3AjEe0'
					)
				),
			]
		);
	}

	/**
	 * Output HTML.
	 *
	 * @since 1.6.2
	 */
	public function output() {

		// We don't need to output tooltip if Challenge is active.
		if ( $this->is_form_embed_page() && $this->is_challenge_active() ) {
			$this->delete_meta();

			return;
		}

		// We don't need to output tooltip if it's not an embed flow.
		if ( $this->is_form_embed_page() && ! $this->get_meta() ) {
			return;
		}

		$template = $this->is_form_embed_page() ? 'admin/form-embed-wizard/tooltip' : 'admin/form-embed-wizard/popup';
		$args     = [];

		if ( ! $this->is_form_embed_page() ) {
			$args['user_can_edit_pages'] = current_user_can( 'edit_pages' );
			$args['dropdown_pages']      = $this->get_select_dropdown_pages_html();
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render( $template, $args );

		$this->delete_meta();
	}

	/**
	 * Check if Challenge is active.
	 *
	 * @since 1.6.4
	 *
	 * @return boolean
	 */
	public function is_challenge_active() {

		static $challenge_active = null;

		if ( $challenge_active === null ) {
			$challenge        = wpforms()->get( 'challenge' );
			$challenge_active = method_exists( $challenge, 'challenge_active' ) ? $challenge->challenge_active() : false;
		}

		return $challenge_active;
	}

	/**
	 * Check if the current page is a form embed page.
	 *
	 * @since 1.6.2
	 *
	 * @param string $type Type of the embed page to check. Can be '', 'add' or 'edit'. By default is empty string.
	 *
	 * @return boolean
	 */
	public function is_form_embed_page( $type = '' ) {

		global $pagenow;

		$type = $type === 'add' || $type === 'edit' ? $type : '';

		if (
			$pagenow !== 'post.php' &&
			$pagenow !== 'post-new.php'
		) {
			return false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$post_id   = empty( $_GET['post'] ) ? 0 : (int) $_GET['post'];
		$post_type = empty( $_GET['post_type'] ) ? '' : sanitize_key( $_GET['post_type'] );
		$action    = empty( $_GET['action'] ) ? 'add' : sanitize_key( $_GET['action'] );
		// phpcs:enable

		if ( $pagenow === 'post-new.php' &&
			( empty( $post_type ) || $post_type !== 'page' )
		) {
			return false;
		}

		if (
			$pagenow === 'post.php' &&
			( empty( $post_id ) || get_post_type( $post_id ) !== 'page' )
		) {
			return false;
		}

		$meta       = $this->get_meta();
		$embed_page = ! empty( $meta['embed_page'] ) ? (int) $meta['embed_page'] : 0;

		if ( 'add' === $action && 0 === $embed_page && $type !== 'edit' ) {
			return true;
		}

		if ( ! empty( $post_id ) && $embed_page === $post_id && $type !== 'add' ) {
			return true;
		}

		return false;
	}

	/**
	 * Set user's embed meta data.
	 *
	 * @since 1.6.2
	 *
	 * @param array $data Data array to set.
	 */
	public function set_meta( $data ) {

		update_user_meta( get_current_user_id(), 'wpforms_admin_form_embed_wizard', $data );
	}

	/**
	 * Get user's embed meta data.
	 *
	 * @since 1.6.2
	 *
	 * @return array User's embed meta data.
	 */
	public function get_meta() {

		return get_user_meta( get_current_user_id(), 'wpforms_admin_form_embed_wizard', true );
	}

	/**
	 * Delete user's embed meta data.
	 *
	 * @since 1.6.2
	 */
	public function delete_meta() {

		delete_user_meta( get_current_user_id(), 'wpforms_admin_form_embed_wizard' );
	}

	/**
	 * Get embed page URL via AJAX.
	 *
	 * @since 1.6.2
	 */
	public function get_embed_page_url_ajax() {

		check_admin_referer( 'wpforms_admin_form_embed_wizard_nonce' );

		$page_id = ! empty( $_POST['pageId'] ) ? absint( $_POST['pageId'] ) : 0;

		if ( ! empty( $page_id ) ) {
			$url  = get_edit_post_link( $page_id, '' );
			$meta = [
				'embed_page' => $page_id,
			];
		} else {
			$url  = add_query_arg( 'post_type', 'page', admin_url( 'post-new.php' ) );
			$meta = [
				'embed_page'       => 0,
				'embed_page_title' => ! empty( $_POST['pageTitle'] ) ? sanitize_text_field( wp_unslash( $_POST['pageTitle'] ) ) : '',
			];
		}

		$meta['form_id'] = ! empty( $_POST['formId'] ) ? absint( $_POST['formId'] ) : 0;

		$this->set_meta( $meta );

		// Update challenge option to properly continue challenge on the embed page.
		if ( $this->is_challenge_active() ) {
			$challenge = wpforms()->get( 'challenge' );
			if ( method_exists( $challenge, 'set_challenge_option' ) ) {
				$challenge->set_challenge_option( [ 'embed_page' => $meta['embed_page'] ] );
			}
		}

		wp_send_json_success( $url );
	}

	/**
	 * Set default title for the new page.
	 *
	 * @since 1.6.2
	 *
	 * @param string   $post_title Default post title.
	 * @param \WP_Post $post       Post object.
	 *
	 * @return string New default post title.
	 */
	public function embed_page_title( $post_title, $post ) {

		$meta = $this->get_meta();

		$this->delete_meta();

		return empty( $meta['embed_page_title'] ) ? $post_title : $meta['embed_page_title'];
	}

	/**
	 * Embed the form to the new page.
	 *
	 * @since 1.6.2
	 *
	 * @param string   $post_content Default post content.
	 * @param \WP_Post $post         Post object.
	 *
	 * @return string Embedding string (shortcode or GB component code).
	 */
	public function embed_page_content( $post_content, $post ) {

		$meta = $this->get_meta();

		$form_id = ! empty( $meta['form_id'] ) ? $meta['form_id'] : 0;
		$page_id = ! empty( $meta['embed_page'] ) ? $meta['embed_page'] : 0;

		if ( ! empty( $page_id ) || empty( $form_id ) ) {
			return $post_content;
		}

		if ( wpforms_is_gutenberg_active() ) {
			$pattern = '<!-- wp:wpforms/form-selector {"formId":"%d"} /-->';
		} else {
			$pattern = '[wpforms id="%d" title="false" description="false"]';
		}

		return sprintf( $pattern, absint( $form_id ) );
	}

	/**
	 * Generate select with pages which are available to edit for current user.
	 *
	 * @since 1.6.6
	 * @since 1.7.9 Refactor to use ChoicesJS instead of `wp_dropdown_pages()`.
	 *
	 * @return string
	 */
	private function get_select_dropdown_pages_html() {

		$dropdown_pages = wpforms_search_posts(
			'',
			[
				'count'       => self::MAX_SEARCH_RESULTS_DROPDOWN_PAGES_COUNT,
				'post_status' => self::POST_STATUSES_OF_DROPDOWN_PAGES,
			]
		);

		if ( empty( $dropdown_pages ) ) {
			return '';
		}

		$total_pages    = 0;
		$wp_count_pages = (array) wp_count_posts( 'page' );

		foreach ( $wp_count_pages as $page_status => $pages_count ) {
			if ( in_array( $page_status, self::POST_STATUSES_OF_DROPDOWN_PAGES, true ) ) {
				$total_pages += $pages_count;
			}
		}

		// Include so we can use `\wpforms_settings_select_callback()`.
		require_once WPFORMS_PLUGIN_DIR . 'includes/admin/settings-api.php';

		return wpforms_settings_select_callback(
			[
				'id'        => 'form-embed-wizard-choicesjs-select-pages',
				'type'      => 'select',
				'choicesjs' => true,
				'options'   => wp_list_pluck( $dropdown_pages, 'post_title', 'ID' ),
				'data'      => [
					'use_ajax' => $total_pages > self::MAX_SEARCH_RESULTS_DROPDOWN_PAGES_COUNT,
				],
			]
		);
	}

	/**
	 * Get search result pages for ChoicesJS via AJAX.
	 *
	 * @since 1.7.9
	 */
	public function get_search_result_pages_ajax() {

		// Run a security check.
		if ( ! check_ajax_referer( 'wpforms_admin_form_embed_wizard_nonce', false, false ) ) {
			wp_send_json_error(
				[
					'msg' => esc_html__( 'Your session expired. Please reload the builder.', 'wpforms-lite' ),
				]
			);
		}

		if ( ! array_key_exists( 'search', $_GET ) ) {
			wp_send_json_error(
				[
					'msg' => esc_html__( 'Incorrect usage of this operation.', 'wpforms-lite' ),
				]
			);
		}

		$result_pages = wpforms_search_pages_for_dropdown(
			sanitize_text_field( wp_unslash( $_GET['search'] ) ),
			[
				'count'       => self::MAX_SEARCH_RESULTS_DROPDOWN_PAGES_COUNT,
				'post_status' => self::POST_STATUSES_OF_DROPDOWN_PAGES,
			]
		);

		if ( empty( $result_pages ) ) {
			wp_send_json_error( [] );
		}

		wp_send_json_success( $result_pages );
	}

	/**
	 * Excludes pages from dropdown which user can't edit.
	 *
	 * @since 1.6.6
	 * @deprecated 1.7.9
	 *
	 * @param WP_Post[] $pages Array of page objects.
	 *
	 * @return WP_Post[]|false Array of filtered pages or false.
	 */
	public function remove_inaccessible_pages( $pages ) {

		_deprecated_function( __METHOD__, '1.7.9 of the WPForms plugin' );

		if ( ! $pages ) {
			return $pages;
		}

		foreach ( $pages as $key => $page ) {
			if ( ! current_user_can( 'edit_page', $page->ID ) ) {
				unset( $pages[ $key ] );
			}
		}

		return $pages;
	}
}
