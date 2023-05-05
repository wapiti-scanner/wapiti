<?php

namespace WPForms\Admin\Builder;

/**
 * Form Builder Keyboard Shortcuts modal content.
 *
 * @since 1.6.9
 */
class Shortcuts {

	/**
	 * Initialize class.
	 *
	 * @since 1.6.9
	 */
	public function init() {

		// Terminate initialization if not in builder.
		if ( ! wpforms_is_admin_page( 'builder' ) ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.9
	 */
	private function hooks() {

		add_filter( 'wpforms_builder_strings', [ $this, 'builder_strings' ], 10, 2 );
		add_action( 'wpforms_admin_page', [ $this, 'output' ], 30 );
	}

	/**
	 * Get shortcuts list.
	 *
	 * @since 1.6.9
	 *
	 * @return array
	 */
	private function get_list() {

		return [
			'left'  => [
				'ctrl s' => __( 'Save Form', 'wpforms-lite' ),
				'ctrl p' => __( 'Preview Form', 'wpforms-lite' ),
				'ctrl b' => __( 'Embed Form', 'wpforms-lite' ),
			],
			'right' => [
				'ctrl h' => __( 'Open Help', 'wpforms-lite' ),
				'ctrl e' => __( 'View Entries', 'wpforms-lite' ),
				'ctrl q' => __( 'Close Builder', 'wpforms-lite' ),
			],
		];
	}

	/**
	 * Add Form builder strings.
	 *
	 * @since 1.6.9
	 *
	 * @param array         $strings Form Builder strings.
	 * @param \WP_Post|bool $form    Form object.
	 *
	 * @return array
	 */
	public function builder_strings( $strings, $form ) {

		$strings['shortcuts_modal_title'] = esc_html__( 'Keyboard Shortcuts', 'wpforms-lite' );
		$strings['shortcuts_modal_msg']   = esc_html__( 'Handy shortcuts for common actions in the builder.', 'wpforms-lite' );

		return $strings;
	}

	/**
	 * Generate and output shortcuts modal content as the wp.template.
	 *
	 * @since 1.6.9
	 */
	public function output() {

		echo '
		<script type="text/html" id="tmpl-wpforms-builder-keyboard-shortcuts">
			<div class="wpforms-columns wpforms-columns-2">';

			foreach ( $this->get_list() as $list ) {

				echo "<ul class='wpforms-column'>";

				foreach ( $list as $key => $label ) {

					$key = explode( ' ', $key );

					printf(
						'<li>
							%1$s
							<span>
								<i>%2$s</i><i>%3$s</i>
							</span>
						</li>',
						esc_html( $label ),
						esc_html( $key[0] ),
						esc_html( $key[1] )
					);
				}

				echo '</ul>';
			}

		echo '
			</div>
		</script>';
	}
}
