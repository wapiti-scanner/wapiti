<?php

namespace WPForms\Lite\Admin\Education\Admin;

use WP_Post;
use WPForms\Admin\Education\EducationInterface;

/**
 * Admin/EditPost Education feature for Lite.
 *
 * @since 1.8.1
 */
class EditPost implements EducationInterface {

	/**
	 * Determine if the website has some forms.
	 *
	 * @since 1.8.1
	 *
	 * @var bool
	 */
	private $has_forms;

	/**
	 * Indicate if edit post education is allowed to load.
	 *
	 * @since 1.8.1
	 *
	 * @return bool
	 */
	public function allow_load() {

		if ( ! is_admin() ) {
			return false;
		}

		if ( ! $this->is_supported_version() ) {
			return false;
		}

		if ( ! wpforms_current_user_can( 'view_forms' ) ) {
			return false;
		}

		// Skip it if it's the Challenge flow.
		if ( wpforms()->get( 'challenge' )->is_form_embed_page() ) {
			return false;
		}

		$form_embed_wizard = wpforms()->get( 'form_embed_wizard' );

		// Skip it if it's the Form Embed Wizard flow.
		if ( $form_embed_wizard->is_form_embed_page( 'edit' ) && $form_embed_wizard->get_meta() ) {
			return false;
		}

		$user_id   = get_current_user_id();
		$dismissed = get_user_meta( $user_id, 'wpforms_dismissed', true );

		return empty( $dismissed['edu-edit-post-notice'] );
	}

	/**
	 * Initialize.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->has_forms = (bool) wpforms()->get( 'form' )->get(
			'',
			[
				'numberposts'            => 1,
				'nopaging'               => false,
				'fields'                 => 'ids',
				'no_found_rows'          => true,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
				'suppress_filters'       => true,
			]
		);

		$this->hooks();
	}

	/**
	 * Add hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		add_action( 'edit_form_after_title', [ $this, 'classic_editor_notice' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_styles' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_scripts' ] );
	}

	/**
	 * Is gutenberg Editor.
	 *
	 * @since 1.8.1
	 *
	 * @return bool
	 */
	private function is_gutenberg_editor() {

		return (bool) get_current_screen()->is_block_editor();
	}

	/**
	 * We support Classic Editor or Block Editor for WordPress 5.5+.
	 *
	 * @since 1.8.1
	 *
	 * @return bool
	 */
	private function is_supported_version() {

		if ( ! $this->is_gutenberg_editor() ) {
			return true;
		}

		global $wp_version;

		return (bool) version_compare( $wp_version, '5.5', '>=' );
	}

	/**
	 * Enqueue styles.
	 *
	 * @since 1.8.1
	 */
	public function enqueue_styles() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-edit-post-education',
			WPFORMS_PLUGIN_URL . "assets/lite/css/admin/edit-post-education{$min}.css",
			[],
			WPFORMS_VERSION
		);
	}

	/**
	 * Enqueue scripts.
	 *
	 * @since 1.8.1
	 */
	public function enqueue_scripts() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-edit-post-education',
			WPFORMS_PLUGIN_URL . "assets/lite/js/admin/edit-post-education.es5{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		$strings = [
			'ajax_url'        => admin_url( 'admin-ajax.php' ),
			'education_nonce' => wp_create_nonce( 'wpforms-education' ),
		];

		if ( $this->is_gutenberg_editor() ) {
			$strings = array_merge( $strings, $this->get_gutenberg_strings() );
		}

		wp_localize_script(
			'wpforms-edit-post-education',
			'wpforms_edit_post_education',
			$strings
		);
	}

	/**
	 * Get Gutenberg i18n strings.
	 *
	 * @since 1.8.1
	 *
	 * @return array
	 */
	private function get_gutenberg_strings() {

		$strings = [
			'gutenberg_notice' => [
				'template' => $this->get_gutenberg_notice_template(),
				'button'   => __( 'Get Started', 'wpforms-lite' ),
			],
		];

		if ( ! $this->has_forms ) {
			$strings['gutenberg_notice']['url'] = add_query_arg( 'page', 'wpforms-overview', admin_url( 'admin.php' ) );

			return $strings;
		}

		$strings['gutenberg_guide'] = [
			[
				'image'   => WPFORMS_PLUGIN_URL . '/assets/lite/images/edit-post-education-page-1.png',
				'title'   => __( 'Easily add your contact form', 'wpforms-lite' ),
				'content' => __( 'Oh hey, it looks like you\'re working on a contact page. Don\'t forget to embed your contact form. Click the plus icon above and search for WPForms.', 'wpforms-lite' ),
			],
			[
				'image'   => WPFORMS_PLUGIN_URL . '/assets/lite/images/edit-post-education-page-2.png',
				'title'   => __( 'Embed your form', 'wpforms-lite' ),
				'content' => __( 'Then click on the WPForms block to embed your desired contact form.', 'wpforms-lite' ),
			],
		];

		return $strings;
	}

	/**
	 * Add notice to classic editor.
	 *
	 * @since 1.8.1
	 *
	 * @param WP_Post $post Add notice to classic editor.
	 */
	public function classic_editor_notice( $post ) {

		$message = $this->has_forms
			? __( 'Don\'t forget to embed your contact form. Simply click the Add Form button below.', 'wpforms-lite' )
			: sprintf( /* translators: %1$s is link to create a new form. */
				__( 'Did you know that with <a href="%1$s" target="_blank" rel="noopener noreferrer">WPForms</a>, you can create an easy-to-use contact form in a matter of minutes?', 'wpforms-lite' ),
				esc_url( add_query_arg( 'page', 'wpforms-overview', admin_url( 'admin.php' ) ) )
			);

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'education/admin/edit-post/classic-notice',
			[
				'message' => $message,
			],
			true
		);
	}

	/**
	 * Get Gutenberg notice template.
	 *
	 * @since 1.8.1
	 *
	 * @return string
	 */
	private function get_gutenberg_notice_template() {

		$message = $this->has_forms
			? __( 'You\'ve already created a form, now add it to the page so your customers can get in touch.', 'wpforms-lite' )
			: sprintf( /* translators: %1$s is link to create a new form. */
				__( 'Did you know that with <a href="%1$s" target="_blank" rel="noopener noreferrer">WPForms</a>, you can create an easy-to-use contact form in a matter of minutes?', 'wpforms-lite' ),
				esc_url( add_query_arg( 'page', 'wpforms-overview', admin_url( 'admin.php' ) ) )
			);

		return wpforms_render(
			'education/admin/edit-post/notice',
			[
				'message' => $message,
			],
			true
		);
	}
}
