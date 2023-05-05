<?php

namespace WPForms\Frontend;

/**
 * Classic render engine class.
 *
 * @since 1.8.1
 */
class Classic {

	/**
	 * Current form data.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	public $form_data;

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	public function hooks() {
	}

	/**
	 * Open form container.
	 *
	 * @since 1.8.1
	 *
	 * @param string|array $classes   Form container classes.
	 * @param array        $form_data Form data.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function form_container_open( $classes, $form_data ) {

		printf(
			'<div class="wpforms-container %s" id="wpforms-%d">',
			wpforms_sanitize_classes( $classes, true ),
			absint( $form_data['id'] )
		);
	}

	/**
	 * Close form container.
	 *
	 * @since 1.8.1
	 */
	public function form_container_close() {

		echo '</div>  <!-- .wpforms-container -->';
	}

	/**
	 * The form has no fields.
	 *
	 * @since 1.8.1
	 */
	public function form_is_empty() {

		echo '<!-- WPForms: no fields, form hidden -->';
	}

	/**
	 * Noscript message.
	 *
	 * @since 1.8.1
	 *
	 * @param string $msg Noscript message.
	 */
	public function noscript( $msg ) {

		printf(
			'<noscript class="wpforms-error-noscript">%s</noscript>',
			esc_html( $msg )
		);
	}


	/**
	 * Display form error.
	 *
	 * @since 1.8.1
	 *
	 * @param string $type  Error type.
	 * @param string $error Error text.
	 */
	public function form_error( $type, $error ) {

		switch ( $type ) {
			case 'header':
			case 'footer':
				// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped
				echo '<div class="wpforms-error-container">' . wpautop( wpforms_sanitize_error( $error ) ) . '</div>';
				// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
				break;

			case 'recaptcha':
				echo '<label id="wpforms-field_recaptcha-error" class="wpforms-error">' . wpforms_sanitize_error( $error ) . '</label>';
				break;
		}
	}

	/**
	 * Open fields area container.
	 *
	 * @since 1.8.1
	 */
	public function fields_area_open() {

		echo '<div class="wpforms-field-container">';
	}

	/**
	 * Close fields area container.
	 *
	 * @since 1.8.1
	 */
	public function fields_area_close() {

		echo '</div><!-- .wpforms-field-container -->';
	}

	/**
	 * Open container for each field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_container_open( $field, $form_data ) {

		$container                     = $field['properties']['container'];
		$container['data']['field-id'] = absint( $field['id'] );

		printf(
			'<div %s>',
			wpforms_html_attributes( $container['id'], $container['class'], $container['data'], $container['attr'] )
		);
	}

	/**
	 * Close container markup for each field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_container_close( $field, $form_data ) {

		echo '</div>';
	}

	/**
	 * Open fieldset.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_fieldset_open( $field, $form_data ) {
	}

	/**
	 * Close fieldset.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_fieldset_close( $field, $form_data ) {
	}

	/**
	 * Field label.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_label( $field, $form_data ) {

		if ( empty( $field['properties']['label'] ) ) {
			return;
		}

		$label    = $field['properties']['label'];
		$required = $label['required'] ? wpforms_get_field_required_label() : '';

		printf(
			'<label %s>%s%s</label>',
			wpforms_html_attributes( $label['id'], $label['class'], $label['data'], $label['attr'] ),
			esc_html( $label['value'] ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$required
		);
	}

	/**
	 * Field error.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_error( $field, $form_data ) {

		if ( empty( $field['properties']['error'] ) ) {
			return;
		}

		$error = $field['properties']['error'];

		printf(
			'<label %s>%s</label>',
			wpforms_html_attributes( $error['id'], $error['class'], $error['data'], $error['attr'] ),
			esc_html( $error['value'] )
		);
	}

	/**
	 * Field description.
	 *
	 * @since 1.8.1
	 *
	 * @param array $field     Field data and settings.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function field_description( $field, $form_data ) {

		if ( empty( $field['properties']['description'] ) ) {
			return;
		}

		$description = $field['properties']['description'];

		printf(
			'<div %s>%s</div>',
			wpforms_html_attributes( $description['id'], $description['class'], $description['data'], $description['attr'] ),
			do_shortcode( $description['value'] )
		);
	}

	/**
	 * Confirmation.
	 *
	 * @since 1.8.1
	 *
	 * @param string $confirmation_message Confirmation message.
	 * @param string $class                CSS class.
	 * @param array  $form_data            Form data and settings.
	 */
	public function confirmation( $confirmation_message, $class, $form_data ) {

		$form_id = isset( $form_data['id'] ) ? $form_data['id'] : 0;

		printf(
			'<div class="%s" id="wpforms-confirmation-%d">%s</div>',
			wpforms_sanitize_classes( $class ),
			absint( $form_id ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$confirmation_message
		);
	}

	/**
	 * Form head container. Form title and description.
	 *
	 * @since 1.8.1
	 *
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $form_data   Form data.
	 */
	public function form_head_container( $title, $description, $form_data ) {

		$settings = $form_data['settings'];

		echo '<div class="wpforms-head-container">';

		if ( $title === true && ! empty( $settings['form_title'] ) ) {
			echo '<div class="wpforms-title">' . esc_html( $settings['form_title'] ) . '</div>';
		}

		if ( $description === true && ! empty( $settings['form_desc'] ) ) {
			echo '<div class="wpforms-description">';
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo wpforms_process_smart_tags( $settings['form_desc'], $form_data );
			echo '</div>';
		}

		echo '</div>';
	}

	/**
	 * Open submit container.
	 *
	 * @since 1.8.1
	 *
	 * @param int   $pages     Information for multi-page forms.
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 * @noinspection HtmlUnknownAttribute
	 */
	public function submit_container_open( $pages, $form_data ) {

		printf( '<div class="wpforms-submit-container" %s>', $pages ? 'style="display:none;"' : '' );
	}

	/**
	 * Submit button.
	 *
	 * @since 1.8.1
	 *
	 * @param int    $form_id    Form ID.
	 * @param string $submit     Submit text.
	 * @param array  $classes    CSS classes.
	 * @param array  $data_attrs Data attributes.
	 * @param array  $attrs      Other attributes.
	 * @param array  $form_data  Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function submit_button( $form_id, $submit, $classes, $data_attrs, $attrs, $form_data ) {

		printf(
			'<button type="submit" name="wpforms[submit]" %s>%s</button>',
			wpforms_html_attributes(
				sprintf( 'wpforms-submit-%d', absint( $form_id ) ),
				$classes,
				$data_attrs,
				$attrs
			),
			esc_html( $submit )
		);
	}

	/**
	 * Submit button.
	 *
	 * @since 1.8.1
	 *
	 * @param string $src       Spinner image src attribute.
	 * @param array  $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function submit_spinner( $src, $form_data ) {

		printf(
			'<img src="%s" class="wpforms-submit-spinner" style="display: none;" width="26" height="26" alt="%s">',
			esc_url( $src ),
			esc_attr__( 'Loading', 'wpforms-lite' )
		);
	}

	/**
	 * Open submit container.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function submit_container_close( $form_data ) {

		echo '</div>';
	}
}
