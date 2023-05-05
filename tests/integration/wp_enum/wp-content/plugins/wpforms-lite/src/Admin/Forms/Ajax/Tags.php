<?php

namespace WPForms\Admin\Forms\Ajax;

use WPForms_Form_Handler;

/**
 * Tags AJAX actions on All Forms page.
 *
 * @since 1.7.5
 */
class Tags {

	/**
	 * Determine if the new tag was added during processing submitted tags.
	 *
	 * @since 1.7.5
	 *
	 * @var bool
	 */
	private $is_new_tag_added;

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function allow_load() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : '';

		// Load only in the case of AJAX calls on Forms Overview page.
		return wp_doing_ajax() && strpos( $action, 'wpforms_admin_forms_overview_' ) === 0;
	}

	/**
	 * Initialize class.
	 *
	 * @since 1.7.5
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		add_action( 'wp_ajax_wpforms_admin_forms_overview_save_tags', [ $this, 'save_tags' ] );
		add_action( 'wp_ajax_wpforms_admin_forms_overview_delete_tags', [ $this, 'delete_tags' ] );
	}

	/**
	 * Save tags.
	 *
	 * @since 1.7.5
	 */
	public function save_tags() {

		$data        = $this->get_prepared_data( 'save' );
		$tags_ids    = $this->get_processed_tags( $data['tags'] );
		$tags_labels = wp_list_pluck( $data['tags'], 'label' );

		// Set tags to each form.
		$this->set_tags_to_forms( $data['forms'], $tags_ids, $tags_labels );

		$tags_obj  = wpforms()->get( 'forms_tags' );
		$terms     = get_the_terms( array_pop( $data['forms'] ), WPForms_Form_Handler::TAGS_TAXONOMY );
		$tags_data = $tags_obj->get_tags_data( $terms );

		if ( ! empty( $this->is_new_tag_added ) ) {
			$tags_data['all_tags_choices'] = $tags_obj->get_all_tags_choices();
		}

		wp_send_json_success( $tags_data );
	}

	/**
	 * Delete tags.
	 *
	 * @since 1.7.5
	 */
	public function delete_tags() {

		$form_obj = wpforms()->get( 'form' );
		$data     = $this->get_prepared_data( 'delete' );
		$deleted  = 0;
		$labels   = [];

		// Get forms marked by the tags.
		$args = [
			'fields'    => 'ids',
			// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_tax_query
			'tax_query' => [
				[
					'taxonomy' => WPForms_Form_Handler::TAGS_TAXONOMY,
					'field'    => 'term_id',
					'terms'    => array_map( 'absint', $data['tags'] ),
				],
			],
		];

		$forms = $form_obj->get( 0, $args );

		foreach ( $data['tags'] as $tag_id ) {
			$term     = get_term_by( 'term_id', $tag_id, WPForms_Form_Handler::TAGS_TAXONOMY, ARRAY_A );
			$labels[] = $term['name'];

			// Delete tag (term).
			if ( wp_delete_term( $tag_id, WPForms_Form_Handler::TAGS_TAXONOMY ) === true ) {
				$deleted++;
			}
		}

		// Remove tags from the settings of the forms.
		foreach ( $forms as $form_id ) {
			$form_data = $form_obj->get( $form_id, [ 'content_only' => true ] );

			if (
				empty( $form_data['settings']['form_tags'] ) ||
				! is_array( $form_data['settings']['form_tags'] )
			) {
				continue;
			}

			$form_data['settings']['form_tags'] = array_diff( $form_data['settings']['form_tags'], $labels );

			$form_obj->update( $form_id, $form_data );
		}

		wp_send_json_success(
			[
				'deleted' => $deleted,
			]
		);
	}

	/**
	 * Get processed tags.
	 *
	 * @since 1.7.5
	 *
	 * @param array $tags_data Submitted tags data.
	 *
	 * @return array Tags IDs list.
	 */
	public function get_processed_tags( $tags_data ) {

		if ( ! is_array( $tags_data ) ) {
			return [];
		}

		$tags_ids = [];

		// Process the tags' data.
		foreach ( $tags_data as $tag ) {

			$term = get_term( $tag['value'], WPForms_Form_Handler::TAGS_TAXONOMY );

			// In the case when the term is not found, we should create the new term.
			if ( empty( $term ) || is_wp_error( $term ) ) {
				$new_term               = wp_insert_term( sanitize_text_field( $tag['label'] ), WPForms_Form_Handler::TAGS_TAXONOMY );
				$tag['value']           = ! is_wp_error( $new_term ) && isset( $new_term['term_id'] ) ? $new_term['term_id'] : 0;
				$this->is_new_tag_added = $this->is_new_tag_added || $tag['value'] > 0;
			}

			if ( ! empty( $tag['value'] ) ) {
				$tags_ids[] = absint( $tag['value'] );
			}
		}

		return $tags_ids;
	}

	/**
	 * Get prepared data before perform ajax action.
	 *
	 * @since 1.7.5
	 *
	 * @param string $action Action: `save` OR `delete`.
	 *
	 * @return array
	 */
	private function get_prepared_data( $action ) {

		// Run a security check.
		if ( ! check_ajax_referer( 'wpforms-admin-forms-overview-nonce', 'nonce', false ) ) {
			wp_send_json_error( esc_html__( 'Most likely, your session expired. Please reload the page.', 'wpforms-lite' ) );
		}

		// Check for permissions.
		if ( ! wpforms_current_user_can( 'edit_forms' ) ) {
			wp_send_json_error( esc_html__( 'You are not allowed to perform this action.', 'wpforms-lite' ) );
		}

		$data = [
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'tags' => ! empty( $_POST['tags'] ) ? map_deep( (array) wp_unslash( $_POST['tags'] ), 'sanitize_text_field' ) : [],
		];

		if ( $action === 'save' ) {
			$data['forms'] = $this->get_allowed_forms();
		}

		return $data;
	}

	/**
	 * Get allowed forms.
	 *
	 * @since 1.7.5
	 *
	 * @return array Allowed form IDs.
	 */
	private function get_allowed_forms() {

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['forms'] ) ) {
			wp_send_json_error( esc_html__( 'No forms selected when trying to add a tag to them.', 'wpforms-lite' ) );
		}

		$forms_all     = array_filter( array_map( 'absint', (array) $_POST['forms'] ) );
		$forms_allowed = [];
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		foreach ( $forms_all as $form_id ) {
			if ( wpforms_current_user_can( 'edit_form_single', $form_id ) ) {
				$forms_allowed[] = $form_id;
			}
		}

		if ( empty( $forms_allowed ) ) {
			wp_send_json_error( esc_html__( 'You are not allowed to perform this action.', 'wpforms-lite' ) );
		}

		return $forms_allowed;
	}

	/**
	 * Set tags to each form in the list.
	 *
	 * @since 1.7.5
	 *
	 * @param array $forms_ids   Forms IDs list.
	 * @param array $tags_ids    Tags IDs list.
	 * @param array $tags_labels Tags labels list.
	 */
	private function set_tags_to_forms( $forms_ids, $tags_ids, $tags_labels ) {

		$form_obj = wpforms()->get( 'form' );

		foreach ( $forms_ids as $form_id ) {
			wp_set_post_terms(
				$form_id,
				$tags_ids,
				WPForms_Form_Handler::TAGS_TAXONOMY
			);

			// Store tags labels in the form settings.
			$form_data                          = $form_obj->get( $form_id, [ 'content_only' => true ] );
			$form_data['settings']['form_tags'] = $tags_labels;

			$form_obj->update( $form_id, $form_data );
		}
	}
}
