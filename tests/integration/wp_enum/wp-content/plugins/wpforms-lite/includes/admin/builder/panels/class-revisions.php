<?php

/**
 * Revisions management panel.
 *
 * @since 1.7.3
 */
class WPForms_Builder_Panel_Revisions extends WPForms_Builder_Panel {

	/**
	 * All systems go.
	 *
	 * @since 1.7.3
	 */
	public function init() {

		// Define panel information.
		$this->name    = esc_html__( 'Revisions', 'wpforms-lite' );
		$this->slug    = 'revisions';
		$this->icon    = 'fa-history';
		$this->order   = 10;
		$this->sidebar = true;

		$this->hooks();
	}

	/**
	 * Hook into WordPress lifecycle.
	 *
	 * @since 1.7.3
	 */
	private function hooks() {

		// Add a notice above all panels if revision is loaded.
		add_action( 'wpforms_builder_panels', [ $this, 'panel_notice' ], 100, 2 );
	}

	/**
	 * Primary panel button in the left panel navigation.
	 *
	 * @since 1.7.3
	 *
	 * @param mixed  $form The form object.
	 * @param string $view Current view/panel.
	 */
	public function button( $form, $view ) {

		$classes = 'wpforms-panel-revisions-button';

		if ( $view === $this->slug ) {
			$classes .= ' active';
		}

		$badge = '';

		if ( $this->form && ! wp_revisions_enabled( $this->form ) && ! wpforms()->get( 'revisions' )->panel_viewed() ) {
			$badge = '
				<span class="badge-exclamation">
					<svg width="4" height="10" fill="none">
						<path fill="#fff" fill-rule="evenodd" d="M3.5 8.1c0-.8-.7-1.5-1.5-1.5S.5 7.3.5 8.1 1.2 9.6 2 9.6 3.5 8.9 3.5 8ZM1 .9c-.3 0-.5.2-.4.4l.2 4.4c0 .2.2.3.4.3h1.6c.2 0 .3-.1.4-.3l.2-4.4c0-.2-.2-.4-.4-.4H1Z" clip-rule="evenodd"/>
					</svg>
				</span>';
		}

		printf(
			'<div class="wpforms-panel-revisions-button-spacer"></div>
			<button class="%1$s" data-panel="%2$s" title="%6$s">
				%3$s
				<i class="fa %4$s"></i>
				<span class="screen-reader-text">%5$s</span>
			</button>',
			esc_attr( $classes ),
			esc_attr( $this->slug ),
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			$badge,
			esc_attr( $this->icon ),
			esc_html( $this->name ),
			esc_html__( 'Form Revisions', 'wpforms-lite' )
		);
	}

	/**
	 * Output the Settings panel sidebar.
	 *
	 * @since 1.7.3
	 */
	public function panel_sidebar() {

		// Sidebar contents are not valid unless we have a form.
		if ( ! $this->form ) {
			return;
		}

		printf(
			'<div class="wpforms-revisions-header">
				<h3>%s</h3>
				<p>%s</p>
			</div>',
			esc_html__( 'Form Revisions', 'wpforms-lite' ),
			esc_html__( 'Select a revision to roll back to that version. All changes, including settings, will be reverted.', 'wpforms-lite' )
		);

		// Render a list of form revisions, including current version. All data is safe, escaped in the template.
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms()->get( 'revisions' )->render_revisions_list();

		$revisions_to_keep = wp_revisions_to_keep( $this->form );

		if ( $revisions_to_keep === 0 ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo wpforms_render( 'builder/revisions/notice-disabled' );
		}

		if ( $revisions_to_keep > 0 ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo wpforms_render(
				'builder/revisions/notice-limited',
				[
					'revisions_to_keep' => $revisions_to_keep,
				],
				true
			);
		}
	}

	/**
	 * Output revision notice above the panels.
	 *
	 * @since 1.7.3
	 *
	 * @return void
	 */
	public function panel_notice() {

		$revision = wpforms()->get( 'revisions' )->get_revision();

		if ( ! $revision ) {
			return;
		}

		$restore_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url(
				wp_nonce_url(
					wpforms()->get( 'revisions' )->get_url(
						[
							'revision_id' => $revision->ID,
							'action'      => 'restore_revision',
						]
					),
					'restore_revision',
					'wpforms_nonce'
				)
			),
			__( 'Restore this revision', 'wpforms-lite' )
		);

		$back_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( wpforms()->get( 'revisions' )->get_url() ),
			__( 'go back to the current version', 'wpforms-lite' )
		);

		$message = sprintf( /* translators: %1$s - revision date, %2$s - revision time, %3$s - "Restore this revision" link, %4$s - "go back to the current version" link. */
			__( 'You’re currently viewing a form revision from %1$s at %2$s. %3$s or %4$s.', 'wpforms-lite' ),
			wpforms()->get( 'revisions' )->get_formatted_datetime( $revision->post_modified_gmt ),
			wpforms()->get( 'revisions' )->get_formatted_datetime( $revision->post_modified_gmt, 'time' ),
			$restore_link,
			$back_link
		);

		printf(
			'<div class="wpforms-revision-notice">
				<p><i class="fa fa-history"></i>%s</p>
			</div>',
			wp_kses(
				$message,
				[
					'a' => [
						'href' => [],
					],
				]
			)
		);
	}
}

new WPForms_Builder_Panel_Revisions();
