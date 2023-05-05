<?php

/**
 * Fields management panel.
 *
 * @since 1.0.0
 */
class WPForms_Builder_Panel_Fields extends WPForms_Builder_Panel {

	/**
	 * All systems go.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define panel information.
		$this->name    = esc_html__( 'Fields', 'wpforms-lite' );
		$this->slug    = 'fields';
		$this->icon    = 'fa-list-alt';
		$this->order   = 10;
		$this->sidebar = true;

		if ( $this->form ) {
			add_action( 'wpforms_builder_fields', [ $this, 'fields' ] );
			add_action( 'wpforms_builder_fields_options', [ $this, 'fields_options' ] );
			add_action( 'wpforms_builder_preview', [ $this, 'preview' ] );

			// Template for form builder previews.
			add_action( 'wpforms_builder_print_footer_scripts', [ $this, 'field_preview_templates' ] );
			add_action( 'wpforms_builder_print_footer_scripts', [ $this, 'choices_limit_message_template' ] );
		}
	}

	/**
	 * Enqueue assets for the Fields panel.
	 *
	 * @since 1.0.0
	 * @since 1.6.8 All the builder stylesheets enqueues moved to the `\WPForms_Builder::enqueues()`.
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-builder-drag-fields',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/builder/drag-fields{$min}.js",
			[ 'wpforms-builder' ],
			WPFORMS_VERSION,
			true
		);
	}

	/**
	 * Output the Field panel sidebar.
	 *
	 * @since 1.0.0
	 */
	public function panel_sidebar() {

		// Sidebar contents are not valid unless we have a form.
		if ( ! $this->form ) {
			return;
		}
		?>
		<ul class="wpforms-tabs wpforms-clear">

			<li class="wpforms-tab" id="add-fields">
				<a href="#" class="active">
					<i class="fa fa-list-alt"></i><?php esc_html_e( 'Add Fields', 'wpforms-lite' ); ?>
				</a>
			</li>

			<li class="wpforms-tab" id="field-options">
				<a href="#">
					<i class="fa fa-sliders"></i><?php esc_html_e( 'Field Options', 'wpforms-lite' ); ?>
				</a>
			</li>

		</ul>

		<div class="wpforms-add-fields wpforms-tab-content">
			<?php do_action( 'wpforms_builder_fields', $this->form ); ?>
		</div>

		<div id="wpforms-field-options" class="wpforms-field-options wpforms-tab-content">
			<?php do_action( 'wpforms_builder_fields_options', $this->form ); ?>
		</div>
		<?php
	}

	/**
	 * Output the Field panel primary content.
	 *
	 * @since 1.0.0
	 */
	public function panel_content() {

		// Check if there is a form created.
		if ( ! $this->form ) {
			echo '<div class="wpforms-alert wpforms-alert-info">';
			echo wp_kses(
				__( 'You need to <a href="#" class="wpforms-panel-switch" data-panel="setup">setup your form</a> before you can manage the fields.', 'wpforms-lite' ),
				[
					'a' => [
						'href'       => [],
						'class'      => [],
						'data-panel' => [],
					],
				]
			);
			echo '</div>';

			return;
		}

		?>

		<div class="wpforms-preview-wrap">

			<div class="wpforms-preview">

				<div class="wpforms-title-desc">
					<div class="wpforms-title-desc-inner">
						<h2 class="wpforms-form-name">
							<?php echo esc_html( isset( $this->form_data['settings']['form_title'] ) ? $this->form_data['settings']['form_title'] : $this->form->post_title ); ?>
						</h2>
						<span class="wpforms-form-desc">
							<?php
							echo wp_kses(
								isset( $this->form_data['settings']['form_desc'] ) ? $this->form_data['settings']['form_desc'] : $this->form->post_excerpt,
								wpforms_builder_preview_get_allowed_tags()
							);
							?>
						</span>
					</div>
				</div>

				<div class="wpforms-no-fields-holder wpforms-hidden">
					<?php $this->no_fields_options(); ?>
					<?php $this->no_fields_preview(); ?>
				</div>

				<div class="wpforms-field-wrap">
					<?php do_action( 'wpforms_builder_preview', $this->form ); ?>
				</div>

				<?php
					$captcha_settings = wpforms_get_captcha_settings();
					$extra_class      = 'is-' . $captcha_settings['provider'];
				?>

				<div class="wpforms-field-recaptcha <?php echo sanitize_html_class( $extra_class ); ?>">
					<div class="wpforms-field-recaptcha-wrap">
						<div class="wpforms-field-recaptcha-wrap-l">
							<svg class="wpforms-field-hcaptcha-icon" fill="none" viewBox="0 0 83 90"><path opacity=".5" d="M60.012 69.998H50.01V80h10.002V69.998z" fill="#0074BF"/><path opacity=".7" d="M50.01 69.998H40.008V80H50.01V69.998zM40.008 69.998H30.006V80h10.002V69.998z" fill="#0074BF"/><path opacity=".5" d="M30.006 69.998H20.004V80h10.002V69.998z" fill="#0074BF"/><path opacity=".7" d="M70.014 60.013H60.014v10.002h10.002V60.012z" fill="#0082BF"/><path opacity=".8" d="M60.012 60.013H50.01v10.002h10.002V60.012z" fill="#0082BF"/><path d="M50.01 60.013H40.008v10.002H50.01V60.012zM40.008 60.013H30.006v10.002h10.002V60.012z" fill="#0082BF"/><path opacity=".8" d="M30.006 60.013H20.004v10.002h10.002V60.012z" fill="#0082BF"/><path opacity=".7" d="M20.004 60.013H10.002v10.002h10.002V60.012z" fill="#0082BF"/><path opacity=".5" d="M80 50.01H69.998v10.002H80V50.01z" fill="#008FBF"/><path opacity=".8" d="M70.014 50.01H60.014v10.002h10.002V50.01z" fill="#008FBF"/><path d="M60.012 50.01H50.01v10.002h10.002V50.01zM50.01 50.01H40.008v10.002H50.01V50.01zM40.008 50.01H30.006v10.002h10.002V50.01zM30.006 50.01H20.004v10.002h10.002V50.01z" fill="#008FBF"/><path opacity=".8" d="M20.004 50.01H10.002v10.002h10.002V50.01z" fill="#008FBF"/><path opacity=".5" d="M10.002 50.01H0v10.002h10.002V50.01z" fill="#008FBF"/><path opacity=".7" d="M80 40.008H69.998V50.01H80V40.008z" fill="#009DBF"/><path d="M70.014 40.008H60.014V50.01h10.002V40.008zM60.012 40.008H50.01V50.01h10.002V40.008zM50.01 40.008H40.008V50.01H50.01V40.008zM40.008 40.008H30.006V50.01h10.002V40.008zM30.006 40.008H20.004V50.01h10.002V40.008zM20.004 40.008H10.002V50.01h10.002V40.008z" fill="#009DBF"/><path opacity=".7" d="M10.002 40.008H0V50.01h10.002V40.008z" fill="#009DBF"/><path opacity=".7" d="M80 30.006H69.998v10.002H80V30.006z" fill="#00ABBF"/><path d="M70.014 30.006H60.014v10.002h10.002V30.006zM60.012 30.006H50.01v10.002h10.002V30.006zM50.01 30.006H40.008v10.002H50.01V30.006zM40.008 30.006H30.006v10.002h10.002V30.006zM30.006 30.006H20.004v10.002h10.002V30.006zM20.004 30.006H10.002v10.002h10.002V30.006z" fill="#00ABBF"/><path opacity=".7" d="M10.002 30.006H0v10.002h10.002V30.006z" fill="#00ABBF"/><path opacity=".5" d="M80 20.004H69.998v10.002H80V20.004z" fill="#00B9BF"/><path opacity=".8" d="M70.014 20.004H60.014v10.002h10.002V20.004z" fill="#00B9BF"/><path d="M60.012 20.004H50.01v10.002h10.002V20.004zM50.01 20.004H40.008v10.002H50.01V20.004zM40.008 20.004H30.006v10.002h10.002V20.004zM30.006 20.004H20.004v10.002h10.002V20.004z" fill="#00B9BF"/><path opacity=".8" d="M20.004 20.004H10.002v10.002h10.002V20.004z" fill="#00B9BF"/><path opacity=".5" d="M10.002 20.004H0v10.002h10.002V20.004z" fill="#00B9BF"/><path opacity=".7" d="M70.014 10.002H60.014v10.002h10.002V10.002z" fill="#00C6BF"/><path opacity=".8" d="M60.012 10.002H50.01v10.002h10.002V10.002z" fill="#00C6BF"/><path d="M50.01 10.002H40.008v10.002H50.01V10.002zM40.008 10.002H30.006v10.002h10.002V10.002z" fill="#00C6BF"/><path opacity=".8" d="M30.006 10.002H20.004v10.002h10.002V10.002z" fill="#00C6BF"/><path opacity=".7" d="M20.004 10.002H10.002v10.002h10.002V10.002z" fill="#00C6BF"/><path opacity=".5" d="M60.012 0H50.01v10.002h10.002V0z" fill="#00D4BF"/><path opacity=".7" d="M50.01 0H40.008v10.002H50.01V0zM40.008 0H30.006v10.002h10.002V0z" fill="#00D4BF"/><path opacity=".5" d="M30.006 0H20.004v10.002h10.002V0z" fill="#00D4BF"/><path d="M26.34 36.84l2.787-6.237c1.012-1.592.88-3.55-.232-4.66a3.6 3.6 0 00-.481-.399 3.053 3.053 0 00-2.571-.298 4.246 4.246 0 00-2.322 1.791s-3.816 8.907-5.242 12.905c-1.426 3.998-.863 11.346 4.611 16.836 5.806 5.806 14.215 7.132 19.573 3.102.232-.116.431-.25.63-.415l16.521-13.8c.797-.664 1.99-2.024.93-3.583-1.046-1.526-3.003-.481-3.816.033l-9.504 6.917a.421.421 0 01-.597-.05s0-.017-.017-.017c-.249-.298-.282-1.078.1-1.393l14.58-12.374c1.26-1.128 1.426-2.787.414-3.915-.995-1.11-2.57-1.078-3.848.067l-13.12 10.267a.578.578 0 01-.813-.083c0-.016-.017-.016-.017-.033-.265-.298-.365-.78-.066-1.078l14.862-14.414c1.178-1.095 1.244-2.936.15-4.097a2.824 2.824 0 00-2.024-.863 2.905 2.905 0 00-2.09.83L39.544 36.144c-.365.364-1.078 0-1.161-.432a.474.474 0 01.132-.431l11.628-13.237a2.86 2.86 0 00.15-4.047 2.86 2.86 0 00-4.048-.15c-.05.05-.1.084-.133.133L28.447 37.47c-.63.63-1.56.664-2.007.299a.657.657 0 01-.1-.929z" fill="#fff"/></svg>
							<svg class="wpforms-field-recaptcha-icon" viewBox="0 0 28 27.918"><path d="M28 13.943l-.016-.607V2l-3.133 3.134a13.983 13.983 0 00-21.964.394l5.134 5.183a6.766 6.766 0 012.083-2.329A6.171 6.171 0 0114.025 7.1a1.778 1.778 0 01.492.066 6.719 6.719 0 015.17 3.119l-3.625 3.641 11.941.016" fill="#1c3aa9"/><path d="M13.943 0l-.607.016H2.018l3.133 3.133a13.969 13.969 0 00.377 21.964l5.183-5.134A6.766 6.766 0 018.382 17.9 6.171 6.171 0 017.1 13.975a1.778 1.778 0 01.066-.492 6.719 6.719 0 013.117-5.167l3.641 3.641L13.943 0" fill="#4285f4"/><path d="M0 13.975l.016.607v11.334l3.133-3.133a13.983 13.983 0 0021.964-.394l-5.134-5.183a6.766 6.766 0 01-2.079 2.33 6.171 6.171 0 01-3.92 1.279 1.778 1.778 0 01-.492-.066 6.719 6.719 0 01-5.167-3.117l3.641-3.641c-4.626 0-9.825.016-11.958-.016" fill="#ababab"/></svg>
							<svg class="wpforms-field-turnstile-icon" fill="none" viewBox="0 0 106 106"> <g clip-path="url(#a)"> <path fill="#F4801F" d="m72.375 76.265.541-1.877c.643-2.231.405-4.29-.678-5.808-1.011-1.397-2.66-2.216-4.68-2.312l-38.213-.486a.743.743 0 0 1-.683-1.012 1.012 1.012 0 0 1 .885-.678l38.583-.506c4.554-.207 9.532-3.92 11.267-8.454l2.196-5.748a1.354 1.354 0 0 0 .061-.779 25.13 25.13 0 0 0-48.312-2.6 11.307 11.307 0 0 0-17.708 11.849A16.054 16.054 0 0 0 .172 76.28a.744.744 0 0 0 .734.643H71.48a.927.927 0 0 0 .895-.658Z"/> <path fill="#F9AB41" d="M85.11 49.82c-.338 0-.692.01-1.063.03a.444.444 0 0 0-.162.035.59.59 0 0 0-.384.405l-1.518 5.191c-.648 2.231-.41 4.29.678 5.808a5.895 5.895 0 0 0 4.675 2.313l8.15.505a.728.728 0 0 1 .577.314.759.759 0 0 1 .086.693 1.012 1.012 0 0 1-.885.678l-8.465.506c-4.599.213-9.552 3.921-11.287 8.45l-.612 1.598a.455.455 0 0 0 .4.617h29.157a.782.782 0 0 0 .779-.592 20.92 20.92 0 0 0-10.822-24.36 20.916 20.916 0 0 0-9.294-2.191h-.01Z"/> </g> <defs> <clipPath id="a"> <path fill="#fff" d="M0 0h106v106H0z"/> </clipPath> </defs> </svg>
						</div>
						<div class="wpforms-field-recaptcha-wrap-r">
							<p class="wpforms-field-hcaptcha-title">hCaptcha</p>
							<p class="wpforms-field-recaptcha-title">reCAPTCHA</p>
							<p class="wpforms-field-turnstile-title">Turnstile</p>
							<p class="wpforms-field-recaptcha-desc">
								<span class="wpforms-field-recaptcha-desc-txt"><?php esc_html_e( 'Enabled', 'wpforms-lite' ); ?></span><svg class="wpforms-field-recaptcha-desc-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><path d="M512 256c0-37.7-23.7-69.9-57.1-82.4 14.7-32.4 8.8-71.9-17.9-98.6-26.7-26.7-66.2-32.6-98.6-17.9C325.9 23.7 293.7 0 256 0s-69.9 23.7-82.4 57.1c-32.4-14.7-72-8.8-98.6 17.9-26.7 26.7-32.6 66.2-17.9 98.6C23.7 186.1 0 218.3 0 256s23.7 69.9 57.1 82.4c-14.7 32.4-8.8 72 17.9 98.6 26.6 26.6 66.1 32.7 98.6 17.9 12.5 33.3 44.7 57.1 82.4 57.1s69.9-23.7 82.4-57.1c32.6 14.8 72 8.7 98.6-17.9 26.7-26.7 32.6-66.2 17.9-98.6 33.4-12.5 57.1-44.7 57.1-82.4zm-144.8-44.25L236.16 341.74c-4.31 4.28-11.28 4.25-15.55-.06l-75.72-76.33c-4.28-4.31-4.25-11.28.06-15.56l26.03-25.82c4.31-4.28 11.28-4.25 15.56.06l42.15 42.49 97.2-96.42c4.31-4.28 11.28-4.25 15.55.06l25.82 26.03c4.28 4.32 4.26 11.29-.06 15.56z"></path></svg>
							</p>
						</div>
					</div>
				</div>

				<?php
				$submit       = ! empty( $this->form_data['settings']['submit_text'] ) ? $this->form_data['settings']['submit_text'] : esc_html__( 'Submit', 'wpforms-lite' );
				$submit_style = empty( $this->form_data['fields'] ) ? 'display: none;' : '';

				printf( '<p class="wpforms-field-submit" style="%1$s"><input type="submit" value="%2$s" class="wpforms-field-submit-button"></p>', esc_attr( $submit_style ), esc_attr( $submit ) );

				/** This action is documented in includes/class-frontend.php. */
				do_action( 'wpforms_display_submit_after', $this->form_data, 'submit' ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
				?>

				<?php wpforms_debug_data( $this->form_data ); ?>
			</div>

		</div>

		<?php
	}

	/**
	 * Builder field buttons.
	 *
	 * @since 1.0.0
	 */
	public function fields() {

		$fields = [
			'standard' => [
				'group_name' => esc_html__( 'Standard Fields', 'wpforms-lite' ),
				'fields'     => [],
			],
			'fancy'    => [
				'group_name' => esc_html__( 'Fancy Fields', 'wpforms-lite' ),
				'fields'     => [],
			],
			'payment'  => [
				'group_name' => esc_html__( 'Payment Fields', 'wpforms-lite' ),
				'fields'     => [],
			],
		];

		/**
		 * Allows developers to modify content of the the Add Field tab.
		 *
		 * With this filter developers can add their own fields or even fields groups.
		 *
		 * @since 1.4.0
		 *
		 * @param array $fields {
		 *     Fields data multidimensional array.
		 *
		 *     @param array $standard Standard fields group.
		 *         @param string $group_name Group name.
		 *         @param array  $fields     Fields array.
		 *
		 *     @param array $fancy    Fancy fields group.
		 *         @param string $group_name Group name.
		 *         @param array  $fields     Fields array.
		 *
		 *     @param array $payment  Payment fields group.
		 *         @param string $group_name Group name.
		 *         @param array  $fields     Fields array.
		 * }
		 */
		$fields = apply_filters( 'wpforms_builder_fields_buttons', $fields );

		// Output the buttons.
		foreach ( $fields as $id => $group ) {

			usort( $group['fields'], [ $this, 'field_order' ] );

			echo '<div class="wpforms-add-fields-group">';

			echo '<a href="#" class="wpforms-add-fields-heading" data-group="' . esc_attr( $id ) . '">';

			echo '<span>' . esc_html( $group['group_name'] ) . '</span>';

			echo '<i class="fa fa-angle-down"></i>';

			echo '</a>';

			echo '<div class="wpforms-add-fields-buttons">';

			foreach ( $group['fields'] as $field ) {
				/**
				 * Attributes of the form field button on the Add Fields tab in the Form Builder.
				 *
				 * @since 1.5.1
				 *
				 * @param array $attributes Field attributes.
				 * @param array $field      Field data.
				 * @param array $form_data  Form data.
				 */
				$atts = apply_filters(
					'wpforms_builder_field_button_attributes',
					[
						'id'    => 'wpforms-add-fields-' . $field['type'],
						'class' => [ 'wpforms-add-fields-button' ],
						'data'  => [
							'field-type' => $field['type'],
						],
						'atts'  => [],
					],
					$field,
					$this->form_data
				);

				if ( ! empty( $field['class'] ) ) {
					$atts['class'][] = $field['class'];
				}

				echo '<button ' . wpforms_html_attributes( $atts['id'], $atts['class'], $atts['data'], $atts['atts'] ) . '>';
					if ( $field['icon'] ) {
						echo '<i class="fa ' . esc_attr( $field['icon'] ) . '"></i> ';
					}
					echo esc_html( $field['name'] );
				echo '</button>';
			}

			echo '</div>';

			echo '</div>';
		}
	}

	/**
	 * Editor Field Options.
	 *
	 * @since 1.0.0
	 */
	public function fields_options() {

		// Check to make sure the form actually has fields created already.
		if ( empty( $this->form_data['fields'] ) ) {
			$this->no_fields_options();

			return;
		}

		$fields = $this->form_data['fields'];

		foreach ( $fields as $field ) {

			$class = apply_filters( 'wpforms_builder_field_option_class', '', $field );

			printf( '<div class="wpforms-field-option wpforms-field-option-%s %s" id="wpforms-field-option-%d" data-field-id="%d">', sanitize_html_class( $field['type'] ), wpforms_sanitize_classes( $class ), (int) $field['id'], (int) $field['id'] );

			printf( '<input type="hidden" name="fields[%d][id]" value="%d" class="wpforms-field-option-hidden-id">', (int) $field['id'], (int) $field['id'] );

			printf( '<input type="hidden" name="fields[%d][type]" value="%s" class="wpforms-field-option-hidden-type">', (int) $field['id'], esc_attr( $field['type'] ) );

			do_action( "wpforms_builder_fields_options_{$field['type']}", $field );

			echo '</div>';
		}
	}

	/**
	 * Editor preview (right pane).
	 *
	 * @since 1.0.0
	 */
	public function preview() {

		// Check to make sure the form actually has fields created already.
		if ( empty( $this->form_data['fields'] ) ) {
			$this->no_fields_preview();

			return;
		}

		/**
		 * Filters the fields which must be displayed on the base level on the preview panel in the Form Builder.
		 *
		 * @since 1.7.7
		 *
		 * @param array $fields Form fields data.
		 */
		$fields = (array) apply_filters( 'wpforms_builder_panel_fields_preview_fields', $this->form_data['fields'] );

		foreach ( $fields as $field ) {

			$this->preview_single_field(
				$field,
				[]
			);
		}
	}

	/**
	 * Preview single field.
	 *
	 * @since 1.7.7
	 *
	 * @param array $field Field data.
	 * @param array $args  Additional arguments.
	 */
	public function preview_single_field( $field, $args ) {

		$class  = ! empty( $field['size'] ) ? 'size-' . esc_attr( $field['size'] ) : '';
		$class .= ! empty( $field['label_hide'] ) ? ' label_hide' : '';
		$class .= isset( $field['label'] ) && empty( $field['label'] ) && $field['type'] !== 'html' ? ' label_empty' : '';
		$class .= ! empty( $field['sublabel_hide'] ) ? ' sublabel_hide' : '';
		$class .= ! empty( $field['required'] ) ? ' required' : '';
		$class .= isset( $field['meta']['delete'] ) && $field['meta']['delete'] === false ? ' no-delete' : '';
		$class .= isset( $field['meta']['duplicate'] ) && $field['meta']['duplicate'] === false ? ' no-duplicate' : '';

		if ( ! empty( $field['input_columns'] ) ) {
			$class .= $field['input_columns'] === '2' ? ' wpforms-list-2-columns' : '';
			$class .= $field['input_columns'] === '3' ? ' wpforms-list-3-columns' : '';
			$class .= $field['input_columns'] === 'inline' ? ' wpforms-list-inline' : '';
		}

		/**
		 * Filters class attribute of the field preview container in the Form Builder.
		 *
		 * @since 1.4.0
		 *
		 * @param string $css   Field preview class.
		 * @param array  $field Field data.
		 */
		$class = apply_filters( 'wpforms_field_preview_class', $class, $field ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		if ( ! has_action( "wpforms_display_field_{$field['type']}" ) ) {
			$this->unavailable_fields_preview( $field );

			return;
		}

		printf(
			'<div class="wpforms-field wpforms-field-%1$s %2$s" id="wpforms-field-%3$d" data-field-id="%3$d" data-field-type="%1$s">',
			esc_attr( $field['type'] ),
			esc_attr( $class ),
			absint( $field['id'] )
		);

		/**
		 * Filters display field duplicate button flag.
		 *
		 * @since 1.5.6.2
		 *
		 * @param bool  $display_duplicate_button Display field duplicate button flag.
		 * @param array $field                    Field data.
		 * @param array $form_data                Form data.
		 */
		if ( apply_filters( 'wpforms_field_preview_display_duplicate_button', true, $field, $this->form_data ) ) { // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			printf(
				'<a href="#" class="wpforms-field-duplicate" title="%s"><i class="fa fa-files-o" aria-hidden="true"></i></a>',
				esc_attr__( 'Duplicate Field', 'wpforms-lite' )
			);
		}

		printf(
			'<a href="#" class="wpforms-field-delete" title="%s"><i class="fa fa-trash-o" aria-hidden="true"></i></a>',
			esc_attr__( 'Delete Field', 'wpforms-lite' )
		);

		if ( empty( $_COOKIE['wpforms_field_helper_hide'] ) ) {
			printf(
				'<div class="wpforms-field-helper">
						<span class="wpforms-field-helper-edit">%s</span>
						<span class="wpforms-field-helper-drag">%s</span>
						<span class="wpforms-field-helper-hide" title="%s">
							<i class="fa fa-times-circle" aria-hidden="true"></i>
						</span>
					</div>',
				esc_html__( 'Click to Edit', 'wpforms-lite' ),
				esc_html__( 'Drag to Reorder', 'wpforms-lite' ),
				esc_attr__( 'Hide Helper', 'wpforms-lite' )
			);
		}

		/**
		 * Fires after the field preview output in the Form Builder.
		 *
		 * @since 1.0.0
		 *
		 * @param array $field Field data.
		 */
		do_action( "wpforms_builder_fields_previews_{$field['type']}", $field ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		echo '</div>';
	}

	/**
	 * Generate HTML for hidden inputs from given data.
	 *
	 * @since 1.6.7
	 *
	 * @param array  $data Field array data.
	 * @param string $name Input name prefix.
	 */
	private function generate_hidden_inputs( $data = [], $name = '' ) {

		if ( ! is_array( $data ) || empty( $data ) ) {
			return;
		}

		foreach ( $data as $key => $value ) {
			if ( $key === 'id' ) {
				continue;
			}

			$key = ! empty( $data['id'] ) ? sprintf( '[%s][%s]', $data['id'], $key ) : sprintf( '[%s]', $key );

			if ( ! empty( $name ) ) {
				$key = trim( $name ) . $key;
			}

			if ( is_array( $value ) ) {
				$this->generate_hidden_inputs( $value, $key );
			} else {
				printf( "<input type='hidden' name='%s' value='%s' />",  esc_attr( $key ), esc_attr( $value ) );
			}
		}
	}

	/**
	 * Unavailable builder field display.
	 *
	 * @since 1.6.7
	 *
	 * @param array $field Field array data.
	 */
	public function unavailable_fields_preview( $field ) {

		// Using ucwords() for certain fields may generate incorrect words.
		switch ( $field['type'] ) {
			case 'url':
				$field_type = 'URL';
				break;

			case 'html':
				$field_type = 'HTML';
				break;

			case 'gdpr-checkbox':
				$field_type = 'GDPR Checkbox';
				break;

			default:
				$field_type = ucwords( preg_replace( '/[_-]/', ' ', $field['type'] ) );
		}

		$warning_message = sprintf( /* translators: %s - unavailable field name. */
			esc_html__( 'Unfortunately, the %s field is not available and will be ignored on the front end.', 'wpforms-lite' ),
			'<b>' . $field_type . '</b>'
		);

		$field_id = isset( $field['id'] ) ? $field['id'] : 0;

		printf(
			'<div class="wpforms-alert wpforms-alert-warning wpforms-alert-dismissible wpforms-alert-field-not-available" data-field-id="%d" data-field-type="unavailable">',
			absint( $field_id )
		);

		printf(
			'<div class="wpforms-alert-message">
				<p>%1$s</p>
			</div>
			<div class="wpforms-alert-buttons">
				<a href="%2$s" target="_blank" rel="noopener noreferrer" class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey">%3$s</a>
				<button type="button" class="wpforms-dismiss-button" title="%4$s" data-field-id="%5$d" />
			</div>',
			$warning_message, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'https://wpforms.com/docs/how-to-import-and-export-wpforms/#field-missing',
			esc_html__( 'Learn More', 'wpforms-lite' ),
			esc_attr__( 'Dismiss this message. The field will be deleted as well.', 'wpforms-lite' ),
			absint( $field_id )
		);

		// Save unavailable fields data in hidden inputs.
		$this->generate_hidden_inputs( $field, 'fields' );

		echo '</div>';
	}

	/**
	 * No fields options markup.
	 *
	 * @since 1.6.0
	 */
	public function no_fields_options() {

		printf(
			'<p class="no-fields wpforms-alert wpforms-alert-warning">%s</p>',
			esc_html__( 'You don\'t have any fields yet.', 'wpforms-lite' )
		);
	}

	/**
	 * No fields preview placeholder markup.
	 *
	 * @since 1.6.0
	 */
	public function no_fields_preview() {

		printf(
			'<div class="no-fields-preview">
				<h4>%1$s</h4>
				<p>%2$s</p>
			</div>',
			esc_html__( 'You don\'t have any fields yet. Add some!', 'wpforms-lite' ),
			esc_html__( 'Take your pick from our wide variety of fields and start building out your form!', 'wpforms-lite' )
		);
	}

	/**
	 * Sort Add Field buttons by order provided.
	 *
	 * @since 1.0.0
	 *
	 * @param array $a First item.
	 * @param array $b Second item.
	 *
	 * @return array
	 */
	public function field_order( $a, $b ) {

		return $a['order'] - $b['order'];
	}

	/**
	 * Template for form builder preview.
	 *
	 * @since 1.4.5
	 */
	public function field_preview_templates() {

		// Checkbox, Radio, and Payment Multiple/Checkbox field choices.
		?>
		<script type="text/html" id="tmpl-wpforms-field-preview-checkbox-radio-payment-multiple">
			<# if ( data.settings.choices_images ) { #>
			<ul class="primary-input wpforms-image-choices wpforms-image-choices-{{ data.settings.choices_images_style }}">
				<# _.each( data.order, function( choiceID, key ) {  #>
				<li class="wpforms-image-choices-item<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' wpforms-selected' ); } #>">
					<label>
						<span class="wpforms-image-choices-image">
							<# if ( ! _.isEmpty( data.settings.choices[choiceID].image ) ) { #>
							<img src="{{ data.settings.choices[choiceID].image }}" alt="{{ data.settings.choices[choiceID].label }}" title="{{ data.settings.choices[choiceID].label }}">
							<# } else { #>
							<img src="{{ wpforms_builder.image_placeholder }}" alt="{{ data.settings.choices[choiceID].label }}" title="{{ data.settings.choices[choiceID].label }}">
							<# } #>
						</span>
						<# if ( 'none' === data.settings.choices_images_style ) { #>
							<br>
							<input type="{{ data.type }}" readonly<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' checked' ); } #>>
						<# } else { #>
							<input class="wpforms-screen-reader-element" type="{{ data.type }}" readonly<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' checked' ); } #>>
						<# } #>
						<span class="wpforms-image-choices-label">
							{{ WPFormsBuilder.fieldChoiceLabel( data, choiceID ) }}
						</span>
					</label>
				</li>
				<# }) #>
			</ul>
			<# } else if ( data.settings.choices_icons ) { #>
			<ul class='primary-input wpforms-icon-choices wpforms-icon-choices-{{ data.settings.choices_icons_style }} wpforms-icon-choices-{{ data.settings.choices_icons_size }}' style="--wpforms-icon-choices-color: {{ data.settings.choices_icons_color }};">
				<# _.each( data.order, function( choiceID, key ) { #>
				<li class="wpforms-icon-choices-item<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' wpforms-selected' ); } #>">
					<label>
						<span class="wpforms-icon-choices-icon">
							<i class="ic-fa-{{ data.settings.choices[choiceID].icon_style }} ic-fa-{{ data.settings.choices[choiceID].icon }}"></i>
							<span class="wpforms-icon-choices-icon-bg"></span>
						</span>
						<# if ( 'none' === data.settings.choices_icons_style ) { #>
							<input type='{{ data.type }}' readonly<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' checked' ); } #>>
						<# } else { #>
							<input class='wpforms-screen-reader-element' type='{{ data.type }}' readonly<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' checked' ); } #>>
						<# } #>
						<span class='wpforms-icon-choices-label'>
							{{ WPFormsBuilder.fieldChoiceLabel( data, choiceID ) }}
						</span>
					</label>
				</li>
				<# }) #>
			</ul>
			<# } else { #>
			<ul class="primary-input">
				<# _.each( data.order, function( choiceID, key ) {  #>
				<li>
					<input type="{{ data.type }}" readonly<# if ( 1 === data.settings.choices[choiceID].default ) { print( ' checked' ); } #>>
					{{ WPFormsBuilder.fieldChoiceLabel( data, choiceID ) }}
				</li>
				<# }) #>
			</ul>
			<# } #>
		</script>
		<?php
	}

	/**
	 * Template for form builder preview.
	 *
	 * @since 1.6.9
	 */
	public function choices_limit_message_template() {

		?>
		<script type="text/html" id="tmpl-wpforms-choices-limit-message">
			<div class="wpforms-alert-dynamic wpforms-alert wpforms-alert-warning">
				<?php
				printf(
					wp_kses( /* translators: %s - total amount of choices. */
						__( 'Showing the first 20 choices.<br> All %s choices will be displayed when viewing the form.', 'wpforms-lite' ),
						[
							'br' => [],
						]
					),
					'{{ data.total }}'
				);
				?>
			</div>
		</script>
		<?php
	}
}

new WPForms_Builder_Panel_Fields();
