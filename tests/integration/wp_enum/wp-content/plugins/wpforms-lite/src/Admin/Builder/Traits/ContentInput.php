<?php

namespace WPForms\Admin\Builder\Traits;

/**
 * Trait ContentInput.
 *
 * @since 1.7.8
 */
trait ContentInput {

	/**
	 * Translatable strings.
	 *
	 * @since 1.7.8
	 *
	 * @var null|array Translatable strings.
	 */
	private static $translatable_strings;

	/**
	 * Constructor overloader to register trait specific hooks.
	 *
	 * @since 1.7.8
	 *
	 * @param bool $init Pass false to allow to shortcut the whole initialization, if needed.
	 */
	public function __construct( $init = true ) {

		if ( ! $init ) {
			return;
		}

		$this->content_input_hooks();
		parent::__construct( $init );
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.7.8
	 */
	private function content_input_hooks() {

		add_action( 'wpforms_builder_enqueues', [ $this, 'builder_enqueues' ] );
		add_action( 'wpforms_builder_print_footer_scripts', [ $this, 'content_editor_tools_template' ] );
		add_filter( 'wpforms_builder_field_option_class', [ $this, 'builder_field_option_class' ], 10, 2 );
		add_filter( 'wpforms_builder_strings', [ $this, 'content_builder_strings' ], 10, 2 );
		add_filter( 'editor_stylesheets', [ $this, 'editor_stylesheets' ] );
		add_filter( 'media_view_strings', [ $this, 'edit_media_view_strings' ], 10, 2 );
		add_filter( 'teeny_mce_buttons', [ $this, 'teeny_mce_buttons' ], 10, 2 );
	}

	/**
	 * Content field option.
	 *
	 * @since 1.7.8
	 *
	 * @param array $field Field data and settings.
	 */
	private function field_option_content( array $field ) {

		$value   = ( isset( $field['content'] ) && ! wpforms_is_empty_string( $field['content'] ) ) ? wp_kses( $field['content'], $this->get_allowed_html_tags() ) : '';
		$output  = $this->field_element(
			'row',
			$field,
			[
				'slug'    => 'content',
				'content' => $this->get_content_editor( $value, $field ),
			],
			false
		);
		$output .= wpforms_render(
			'fields/content/action-buttons',
			[
				'id'      => $field['id'],
				'preview' => $this->get_input_string( 'preview' ),
				'expand'  => $this->get_input_string( 'expand' ),
			],
			true
		);

		printf( '<div class="wpforms-expandable-editor">%s</div><div class="wpforms-expandable-editor-clear"></div>', $output ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}

	/**
	 * Add class name to the field option top element.
	 *
	 * @since 1.7.8
	 *
	 * @param string $class CSS classes.
	 * @param array  $field Field data.
	 */
	public function builder_field_option_class( $class, $field ) {

		return $this->type === $field['type'] ? $class . ' wpforms-field-has-tinymce' : $class;
	}

	/**
	 * Localized strings for content-field JS script.
	 *
	 * @since 1.7.8
	 *
	 * @param array $strings Localized strings.
	 * @param array $form    The form element.
	 *
	 * @return array
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function content_builder_strings( $strings, $form ) {

		$strings['content_field'] = [
			'collapse'               => wp_strip_all_tags( $this->get_input_string( 'collapse' ) ),
			'expand'                 => wp_strip_all_tags( $this->get_input_string( 'expand' ) ),
			'editor_default_value'   => wp_kses( $this->get_input_string( 'editor_default_value' ), $this->get_allowed_html_tags() ),
			'content_editor_plugins' => $this->content_editor_plugins(),
			'content_editor_toolbar' => $this->content_editor_toolbar(),
			'content_editor_css_url' => $this->content_css_url(),
			'editor_height'          => $this->get_editor_height(),
			'allowed_html'           => array_keys( $this->get_allowed_html_tags() ),
			'invalid_elements'       => $this->get_invalid_elements(),
			'quicktags_buttons'      => $this->get_quicktags_buttons(),
			'body_class'             => $this->get_editor_body_class(),
		];

		$strings = $this->add_supported_field_type( $strings, $this->type );

		return $strings;
	}

	/**
	 * Add editor stylesheet.
	 *
	 * @since 1.7.8
	 *
	 * @param array $stylesheets Editor stylesheets.
	 *
	 * @return array
	 */
	public function editor_stylesheets( $stylesheets ) {

		if ( wpforms_is_admin_page( 'builder' ) ) {
			$stylesheets[] = $this->content_css_url();
		}

		return $stylesheets;
	}

	/**
	 * Edit some media view strings to reference a form instead of a page/post.
	 *
	 * @since 1.7.8
	 *
	 * @param array   $strings List of media view strings.
	 * @param WP_Post $post    Post object.
	 *
	 * @return array Modified media view strings.
	 */
	public function edit_media_view_strings( $strings, $post ) {

		if ( wpforms_is_admin_page( 'builder' ) ) {
			$strings['insertIntoPost']     = esc_html__( 'Insert into form', 'wpforms-lite' );
			$strings['uploadedToThisPost'] = esc_html__( 'Uploaded to this form', 'wpforms-lite' );
		}

		return $strings;
	}

	/**
	 * Remove fullscreen button if this is other tinymce editor instance than content field editor.
	 *
	 * @since 1.7.8
	 *
	 * @param array  $buttons   Array of editor buttons.
	 * @param string $editor_id Editor textarea ID.
	 *
	 * @return array
	 */
	public function teeny_mce_buttons( $buttons, $editor_id ) {

		$is_other_editor = strpos( $editor_id, 'wpforms_panel_' ) === 0 || $editor_id === 'entry_note';
		$key             = array_search( 'fullscreen', $buttons, true );

		if ( $is_other_editor && $key !== false ) {
			unset( $buttons[ $key ] );
		}

		return $buttons;
	}

	/**
	 * Get default content editor plugins.
	 *
	 * @since 1.7.8
	 *
	 * @return array Plugins array.
	 */
	private function content_editor_plugins() {

		$plugins = [
			'charmap',
			'colorpicker',
			'hr',
			'link',
			'image',
			'lists',
			'paste',
			'tabfocus',
			'textcolor',
			'wordpress',
			'wpemoji',
			'wptextpattern',
			'wpeditimage',
		];

		/**
		 * Get content editor plugins filter.
		 *
		 * @since 1.7.8
		 *
		 * @param array $plugins Plugins array.
		 */
		return (array) apply_filters( 'wpforms_builder_content_input_get_content_editor_plugins', $plugins );
	}

	/**
	 * Get default content editor toolbar.
	 *
	 * @since 1.7.8
	 *
	 * @return array Toolbar buttons array.
	 */
	private function content_editor_toolbar() {

		$toolbar = [
			'formatselect',
			'bold',
			'italic',
			'underline',
			'strikethrough',
			'forecolor',
			'link',
			'bullist',
			'numlist',
			'blockquote',
			'alignleft',
			'aligncenter',
			'alignright',
		];

		/**
		 * Get content editor toolbar buttons filter.
		 *
		 * @since 1.7.8
		 *
		 * @param array $toolbar Toolbar buttons array.
		 */
		return (array) apply_filters( 'wpforms_builder_content_input_get_content_editor_toolbar', $toolbar );
	}

	/**
	 * Enqueue wpforms-content-field script.
	 *
	 * @since 1.7.8
	 *
	 * @param string $view Current view.
	 *
	 * @noinspection PhpUnusedParameterInspection, PhpUnnecessaryCurlyVarSyntaxInspection
	 */
	public function builder_enqueues( $view ) {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-content-field',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/fields/content-field{$min}.js",
			[ 'wpforms-builder', 'editor', 'quicktags' ],
			WPFORMS_VERSION,
			true
		);

		// Enqueue editor styles explicitly. Hack for broken styles when Content field is deleted and Settings > Confirmation editor get broken.
		wp_enqueue_style(
			'wpforms-editor-styles',
			includes_url( 'css/editor.css' )
		);
	}

	/**
	 * Content editor tools template.
	 *
	 * @since 1.7.8
	 */
	public function content_editor_tools_template() {

		?>
		<script type="text/html" id="tmpl-wpforms-content-editor-tools">
			<div id="wp-wpforms-field-{{data.optionId}}-content-editor-tools" class="wp-editor-tools hide-if-no-js">
				<div id="wp-wpforms-field-{{data.optionId}}-content-media-buttons" class="wp-media-buttons">
					<button type="button" id="insert-media-button" class="button insert-media add_media" data-editor="wpforms-field-{{data.optionId}}-content">
						<span class="wp-media-buttons-icon"></span>
						<?php esc_html_e( 'Add Media', 'wpforms-lite' ); ?>
					</button>
				</div>
				<div class="wp-editor-tabs">
					<button type="button" id="wpforms-field-{{data.optionId}}-content-tmce" class="wp-switch-editor switch-tmce" data-wp-editor-id="wpforms-field-{{data.optionId}}-content">
						<?php esc_html_e( 'Visual', 'wpforms-lite' ); ?>
					</button>
					<button type="button" id="wpforms-field-{{data.optionId}}-content-html" class="wp-switch-editor switch-html" data-wp-editor-id="wpforms-field-{{data.optionId}}-content">
						<?php esc_html_e( 'Text', 'wpforms-lite' ); ?>
					</button>
				</div>
			</div>
		</script>
		<?php
	}

	/**
	 * Register types in JS localisation to use in WPFormsContentField.
	 *
	 * @since 1.7.8
	 *
	 * @param array  $strings Localized strings.
	 * @param string $type    Field type.
	 *
	 * @return array
	 */
	private function add_supported_field_type( $strings, $type ) {

		$other_supported_field_types = isset( $strings['content_input']['supported_field_types'] ) ? $strings['content_input']['supported_field_types'] : [];

		$strings['content_input'] = [
			'supported_field_types' => array_merge( $other_supported_field_types, [ $type ] ),
		];

		return $strings;
	}

	/**
	 * Get translatable string.
	 *
	 * @since 1.7.8
	 *
	 * @param string $key String key.
	 *
	 * @return string
	 */
	private function get_input_string( $key ) {

		if ( ! self::$translatable_strings ) {
			self::$translatable_strings = [
				'editor_default_value' => __( '<h4>Add Text and Images to Your Form With Ease</h4> <p>To get started, replace this text with your own.</p>', 'wpforms-lite' ),
				'expand'               => __( 'Expand Editor', 'wpforms-lite' ),
				'collapse'             => __( 'Collapse Editor', 'wpforms-lite' ),
				'preview'              => __( 'Update Preview', 'wpforms-lite' ),
			];
		}

		return isset( self::$translatable_strings[ $key ] ) ? self::$translatable_strings[ $key ] : '';
	}

	/**
	 * Show field preview in the right builder panel.
	 *
	 * @since 1.7.8
	 *
	 * @param array $field Field data.
	 */
	private function content_input_preview( $field ) {

		$content = isset( $field['content'] ) ? $field['content'] : $this->get_input_string( 'editor_default_value' );
		?>
		<div class="wpforms-field-content-preview">
			<?php echo wp_kses( $this->do_caption_shortcode( wpautop( $content ) ), $this->get_allowed_html_tags() ); ?>
			<div class="wpforms-field-content-preview-end"></div>
		</div>
		<?php
	}

	/**
	 * Check if shortcode is [caption] and if not, return processed content string.
	 *
	 * @since 1.7.8
	 *
	 * @param false|string $return Short-circuit return value. Either false or the value to replace the shortcode with.
	 * @param string       $tag    Shortcode name.
	 * @param array|string $attr   Shortcode attributes array or empty string.
	 * @param array        $m      Regular expression match array.
	 *
	 * @return false|string
	 */
	public function short_circuit_shortcodes( $return, $tag, $attr, $m ) {

		return $tag !== 'caption' ? $m[0] : false;
	}

	/**
	 * Check if shortcode is [caption] and if not, short-circuit processing the shortcode.
	 *
	 * @since 1.7.8
	 *
	 * @param string $content Editor content.
	 *
	 * @return string
	 */
	private function do_caption_shortcode( $content ) {

		/**
		 * Check if user allowed to execute all shortcodes on content field value.
		 *
		 * @since 1.7.8
		 *
		 * @param bool $bool Boolean if shortcodes should be executed.
		 */
		if ( apply_filters( 'wpforms_content_input_value_do_shortcode', false ) && ! wpforms_is_admin_page( 'builder' ) ) {
			return do_shortcode( $content );
		}

		add_filter( 'pre_do_shortcode_tag', [ $this, 'short_circuit_shortcodes' ], 10, 4 );

		$content = do_shortcode( $content );

		remove_filter( 'pre_do_shortcode_tag', [ $this, 'short_circuit_shortcodes' ] );

		return $content;
	}

	/**
	 * Get TinyMCE editor for content field.
	 *
	 * @since 1.7.8
	 *
	 * @param string $value Field value.
	 * @param array  $field Field data.
	 *
	 * @return string
	 */
	private function get_content_editor( $value, $field ) {
		/*
		Heads up, if you are going to edit editor settings, bear in mind editor is instantiated in two places:
		- PHP instance in \WPForms\Admin\Builder\Traits\ContentInput::get_content_editor
		- JS instance in WPForms.Admin.Builder.ContentField.initTinyMCE
		*/
		$settings = [
			'media_buttons'    => true,
			'drag_drop_upload' => true,
			'textarea_name'    => "fields[{$field['id']}][content]",
			'editor_height'    => $this->get_editor_height(),
			'editor_class'     => ! empty( $field['required'] ) ? 'wpforms-field-required' : '',
			'tinymce'          => [
				'init_instance_callback' => 'wpformsContentFieldTinyMCECallback',
				'plugins'                => implode( ',', $this->content_editor_plugins() ),
				'toolbar1'               => implode( ',', $this->content_editor_toolbar() ),
				'invalid_elements'       => $this->get_invalid_elements(),
				'relative_urls'          => false,
				'remove_script_host'     => false,
				'object_resizing'        => false,
				'body_class'             => $this->get_editor_body_class(),
			],
			'quicktags'        => [
				'buttons' => $this->get_quicktags_buttons(),
			],
		];

		ob_start();
		wp_editor( $value, 'wpforms-field-option-' . $field['id'] . '-content', $settings );

		return ob_get_clean();
	}

	/**
	 * Get invalid HTML in content editor.
	 *
	 * @since 1.7.8
	 *
	 * @return string Invalid HTML elements.
	 */
	private function get_invalid_elements() {

		return 'form,input,textarea,select,option,script,embed,iframe';
	}

	/**
	 * Get list of quicktags buttons.
	 *
	 * @since 1.7.8
	 *
	 * @return string Quicktags buttons.
	 */
	private function get_quicktags_buttons() {

		$quicktag_buttons = [
			'strong',
			'em',
			'block',
			'del',
			'ins',
			'img',
			'ul',
			'ol',
			'li',
			'code',
			'link',
			'close',
		];

		/**
		 * Get list of quicktags buttons filter.
		 *
		 * @since 1.7.8
		 *
		 * @param string $quicktags_buttons Comma separated list of quicktags buttons.
		 */
		return implode( ',', apply_filters( 'wpforms_builder_content_input_get_quicktags_buttons', $quicktag_buttons ) );
	}

	/**
	 * Get content CSS url.
	 *
	 * @since 1.7.8
	 *
	 * @return string
	 */
	private function content_css_url() {

		$min = wpforms_get_min_suffix();

		return WPFORMS_PLUGIN_URL . "assets/css/builder/content-editor{$min}.css";
	}

	/**
	 * Get content editor height.
	 *
	 * @since 1.7.8
	 *
	 * @retun int Editor textarea height.
	 */
	private function get_editor_height() {

		/**
		 * Get content editor height filter.
		 *
		 * @since 1.7.8
		 *
		 * @param int $height Editor textarea height.
		 */
		return (int) apply_filters( 'wpforms_builder_content_input_get_editor_height', 204 );
	}

	/**
	 * Get allowed HTML tags for Content Input Field.
	 *
	 * @since 1.7.8
	 *
	 * @return array
	 */
	private function get_allowed_html_tags() {

		/**
		 * Filter allowed HTML tags in the content field input.
		 *
		 * @since 1.7.8
		 *
		 * @param array $allowed_tags Allowed tags.
		 */
		return (array) apply_filters( 'wpforms_builder_content_input_get_allowed_html_tags', wpforms_get_allowed_html_tags_for_richtext_field() );
	}

	/**
	 * Get editor body class.
	 *
	 * @since 1.7.9
	 *
	 * @return string
	 */
	private function get_editor_body_class() {

		return 'wpforms-content-field-editor-body';
	}
}
