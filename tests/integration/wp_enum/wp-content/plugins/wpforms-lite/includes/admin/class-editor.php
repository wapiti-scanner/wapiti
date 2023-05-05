<?php

/**
 * Functionality related to the admin TinyMCE editor.
 *
 * @since 1.0.0
 */
class WPForms_Admin_Editor {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		add_action( 'media_buttons', [ $this, 'media_button' ], 15 );
	}

	/**
	 * Allow easy shortcode insertion via a custom media button.
	 *
	 * @since 1.0.0
	 *
	 * @param string $editor_id Editor Id.
	 */
	public function media_button( $editor_id ) {

		if ( ! \wpforms_current_user_can( 'view_forms' ) ) {
			return;
		}

		// Provide the ability to conditionally disable the button, so it can be
		// disabled for custom fields or front-end use such as bbPress. We default
		// to only showing within the post editor page.
		if ( ! apply_filters( 'wpforms_display_media_button', $this->is_post_editor_page(), $editor_id ) ) {
			return;
		}

		// Setup the icon - currently using a dashicon.
		$icon = '<span class="wp-media-buttons-icon wpforms-menu-icon" style="font-size:16px;margin-top:-2px;"><svg width="18" height="18" viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path d="M643 911v128h-252v-128h252zm0-255v127h-252v-127h252zm758 511v128h-341v-128h341zm0-256v128h-672v-128h672zm0-255v127h-672v-127h672zm135 860v-1240q0-8-6-14t-14-6h-32l-378 256-210-171-210 171-378-256h-32q-8 0-14 6t-6 14v1240q0 8 6 14t14 6h1240q8 0 14-6t6-14zm-855-1110l185-150h-406zm430 0l221-150h-406zm553-130v1240q0 62-43 105t-105 43h-1240q-62 0-105-43t-43-105v-1240q0-62 43-105t105-43h1240q62 0 105 43t43 105z" fill="#82878c"/></svg></span>';

		printf(
			'<a href="#" class="button wpforms-insert-form-button" data-editor="%s" title="%s">%s %s</a>',
			esc_attr( $editor_id ),
			esc_attr__( 'Add Form', 'wpforms-lite' ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$icon,
			esc_html__( 'Add Form', 'wpforms-lite' )
		);

		$min = wpforms_get_min_suffix();

		// If we have made it this far then load the JS.
		wp_enqueue_script(
			'wpforms-editor',
			WPFORMS_PLUGIN_URL . "assets/js/admin-editor{$min}.js",
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);

		add_action( 'admin_footer', [ $this, 'shortcode_modal' ] );
	}

	/**
	 * Check if we are on the post editor admin page.
	 *
	 * @since 1.6.2
	 *
	 * @returns boolean True if it is post editor admin page.
	 */
	public function is_post_editor_page() {

		if ( ! is_admin() ) {
			return false;
		}

		// get_current_screen() is loaded after 'admin_init' hook and may not exist yet.
		if ( ! function_exists( 'get_current_screen' ) ) {
			return false;
		}

		$screen = get_current_screen();

		return $screen !== null && $screen->parent_base === 'edit';
	}

	/**
	 * Modal window for inserting the form shortcode into TinyMCE.
	 *
	 * Thickbox is old and busted so we don't use that. Creating a custom view in
	 * Backbone would make me pull my hair out. So instead we offer a small clean
	 * modal that is based off of the WordPress insert link modal.
	 *
	 * @since 1.0.0
	 */
	public function shortcode_modal() {
		?>
		<div id="wpforms-modal-backdrop" style="display: none"></div>
		<div id="wpforms-modal-wrap" style="display: none">
			<form id="wpforms-modal" tabindex="-1">
				<div id="wpforms-modal-title">
					<?php esc_html_e( 'Insert Form', 'wpforms-lite' ); ?>
					<button type="button" id="wpforms-modal-close"><span class="screen-reader-text"><?php esc_html_e( 'Close', 'wpforms-lite' ); ?></span></button>
				</div>
				<div id="wpforms-modal-inner">

					<div id="wpforms-modal-options">
						<?php
						echo '<p id="wpforms-modal-notice">';
						printf(
							wp_kses( /* translators: %s - WPForms documentation URL. */
								__( 'Heads up! Don\'t forget to test your form. <a href="%s" target="_blank" rel="noopener noreferrer">Check out our complete guide</a>!', 'wpforms-lite' ),
								[
									'a' => [
										'href'   => [],
										'rel'    => [],
										'target' => [],
									],
								]
							),
							'https://wpforms.com/docs/how-to-properly-test-your-wordpress-forms-before-launching-checklist/'
						);
						echo '</p>';
						$args  = apply_filters( 'wpforms_modal_select', [] );
						$forms = wpforms()->form->get( '', $args );
						if ( ! empty( $forms ) ) {
							printf( '<p><label for="wpforms-modal-select-form">%s</label></p>', esc_html__( 'Select a form below to insert', 'wpforms-lite' ) );
							echo '<select id="wpforms-modal-select-form">';
							foreach ( $forms as $form ) {
								printf( '<option value="%d">%s</option>', $form->ID, esc_html( $form->post_title ) );
							}
							echo '</select><br>';
							printf( '<p class="wpforms-modal-inline"><input type="checkbox" id="wpforms-modal-checkbox-title"><label for="wpforms-modal-checkbox-title">%s</label></p>', esc_html__( 'Show form name', 'wpforms-lite' ) );
							printf( '<p class="wpforms-modal-inline"><input type="checkbox" id="wpforms-modal-checkbox-description"><label for="wpforms-modal-checkbox-description">%s</label></p>', esc_html__( 'Show form description', 'wpforms-lite' ) );
						} else {
							echo '<p>';
							printf(
								wp_kses(
									/* translators: %s - WPForms Builder page. */
									__( 'Whoops, you haven\'t created a form yet. Want to <a href="%s">give it a go</a>?', 'wpforms-lite' ),
									[
										'a' => [
											'href' => [],
										],
									]
								),
								admin_url( 'admin.php?page=wpforms-builder' )
							);
							echo '</p>';
						}
						?>
					</div>
				</div>
				<div class="submitbox">
					<div id="wpforms-modal-cancel">
						<a class="submitdelete deletion" href="#"><?php esc_html_e( 'Cancel', 'wpforms-lite' ); ?></a>
					</div>
					<?php if ( ! empty( $forms ) ) : ?>
						<div id="wpforms-modal-update">
							<button class="button button-primary" id="wpforms-modal-submit"><?php esc_html_e( 'Add Form', 'wpforms-lite' ); ?></button>
						</div>
					<?php endif; ?>
				</div>
			</form>
		</div>
		<style type="text/css">
			.wpforms-insert-form-button svg path {
				fill: #0071a1;
			}

			.wpforms-insert-form-button:hover svg path {
				fill: #016087;
			}

			#wpforms-modal-wrap {
				display: none;
				background-color: #fff;
				-webkit-box-shadow: 0 3px 6px rgba(0, 0, 0, 0.3);
				box-shadow: 0 3px 6px rgba(0, 0, 0, 0.3);
				width: 500px;
				height: 285px;
				overflow: hidden;
				margin-left: -250px;
				margin-top: -125px;
				position: fixed;
				top: 50%;
				left: 50%;
				z-index: 100205;
				-webkit-transition: height 0.2s, margin-top 0.2s;
				transition: height 0.2s, margin-top 0.2s;
			}

			#wpforms-modal-backdrop {
				display: none;
				position: fixed;
				top: 0;
				left: 0;
				right: 0;
				bottom: 0;
				min-height: 360px;
				background: #000;
				opacity: 0.7;
				filter: alpha(opacity=70);
				z-index: 100200;
			}

			#wpforms-modal {
				position: relative;
				height: 100%;
			}

			#wpforms-modal-title {
				background: #fcfcfc;
				border-bottom: 1px solid #dfdfdf;
				height: 36px;
				font-size: 18px;
				font-weight: 600;
				line-height: 36px;
				padding: 0 36px 0 16px;
				top: 0;
				right: 0;
				left: 0;
			}

			#wpforms-modal-close {
				color: #666;
				padding: 0;
				position: absolute;
				top: 0;
				right: 0;
				width: 36px;
				height: 36px;
				text-align: center;
				background: none;
				border: none;
				cursor: pointer;
			}

			#wpforms-modal-close:before {
				font: normal 20px/36px 'dashicons';
				vertical-align: top;
				speak: none;
				-webkit-font-smoothing: antialiased;
				-moz-osx-font-smoothing: grayscale;
				width: 36px;
				height: 36px;
				content: '\f158';
			}

			#wpforms-modal-close:hover,
			#wpforms-modal-close:focus {
				color: #2ea2cc;
			}

			#wpforms-modal-close:focus {
				outline: none;
				-webkit-box-shadow: 0 0 0 1px #5b9dd9,
				0 0 2px 1px rgba(30, 140, 190, .8);
				box-shadow: 0 0 0 1px #5b9dd9,
				0 0 2px 1px rgba(30, 140, 190, .8);
			}

			#wpforms-modal-inner {
				padding: 0 16px 50px;
			}

			#wpforms-modal-search-toggle:after {
				display: inline-block;
				font: normal 20px/1 'dashicons';
				vertical-align: top;
				speak: none;
				-webkit-font-smoothing: antialiased;
				-moz-osx-font-smoothing: grayscale;
				content: '\f140';
			}

			#wpforms-modal-notice {
				background-color: #d9edf7;
				border: 1px solid #bce8f1;
				color: #31708f;
				padding: 10px;
			}

			#wpforms-modal #wpforms-modal-options {
				padding: 8px 0 12px;
			}

			#wpforms-modal #wpforms-modal-options .wpforms-modal-inline {
				display: inline-block;
				margin: 0;
				padding: 0 20px 0 0;
			}

			#wpforms-modal-select-form {
				margin-bottom: 1em;
				max-width: 100%;
			}

			#wpforms-modal .submitbox {
				padding: 8px 16px;
				background: #fcfcfc;
				border-top: 1px solid #dfdfdf;
				position: absolute;
				bottom: 0;
				left: 0;
				right: 0;
			}

			#wpforms-modal-cancel {
				line-height: 25px;
				float: left;
			}

			#wpforms-modal-update {
				line-height: 23px;
				float: right;
			}

			#wpforms-modal-submit {
				float: right;
				margin-bottom: 0;
			}

			@media screen and ( max-width: 782px ) {
				#wpforms-modal-wrap {
					height: 280px;
					margin-top: -140px;
				}

				#wpforms-modal-inner {
					padding: 0 16px 60px;
				}

				#wpforms-modal-cancel {
					line-height: 32px;
				}
			}

			@media screen and ( max-width: 520px ) {
				#wpforms-modal-wrap {
					width: auto;
					margin-left: 0;
					left: 10px;
					right: 10px;
					max-width: 500px;
				}
			}

			@media screen and ( max-height: 520px ) {
				#wpforms-modal-wrap {
					-webkit-transition: none;
					transition: none;
				}
			}

			@media screen and ( max-height: 290px ) {
				#wpforms-modal-wrap {
					height: auto;
					margin-top: 0;
					top: 10px;
					bottom: 10px;
				}

				#wpforms-modal-inner {
					overflow: auto;
					height: -webkit-calc(100% - 92px);
					height: calc(100% - 92px);
					padding-bottom: 2px;
				}
			}
		</style>
		<?php
	}

}

new WPForms_Admin_Editor();
