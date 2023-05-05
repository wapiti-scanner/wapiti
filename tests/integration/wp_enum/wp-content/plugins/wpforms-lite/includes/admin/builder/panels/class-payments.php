<?php

/**
 * Payments panel.
 *
 * @since 1.0.0
 */
class WPForms_Builder_Panel_Payments extends WPForms_Builder_Panel {

	/**
	 * All systems go.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Define panel information.
		$this->name    = esc_html__( 'Payments', 'wpforms-lite' );
		$this->slug    = 'payments';
		$this->icon    = 'fa-usd';
		$this->order   = 10;
		$this->sidebar = true;
	}

	/**
	 * Output the Payments panel sidebar.
	 *
	 * @since 1.0.0
	 */
	public function panel_sidebar() {

		// Sidebar contents are not valid unless we have a form.
		if ( ! $this->form ) {
			return;
		}

		$this->panel_sidebar_section( esc_html__( 'Default', 'wpforms-lite' ), 'default' );

		do_action( 'wpforms_payments_panel_sidebar', $this->form );
	}

	/**
	 * Output the Payments panel primary content.
	 *
	 * @since 1.0.0
	 */
	public function panel_content() {

		// An array of all the active provider addons.
		$payments_active = apply_filters( 'wpforms_payments_available', [] );

		if ( ! $this->form ) {

			// Check if there is a form created. When no form has been created
			// yet let the user know we need a form to setup a payment.
			echo '<div class="wpforms-alert wpforms-alert-info">';
				echo wp_kses(
					__( 'You need to <a href="#" class="wpforms-panel-switch" data-panel="setup">setup your form</a> before you can manage these settings.', 'wpforms-lite' ),
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

		if ( ! wpforms()->is_pro() ) {

			// WPForms Lite users.
			echo '<div class="wpforms-panel-content-section wpforms-panel-content-section-info">
				<div class="illustration illustration-payments"></div>
				<h5>' . esc_html__( 'Payment integrations are not available on your plan.', 'wpforms-lite' ) . '</h5>
				<p>' . esc_html__( 'Please upgrade to PRO to unlock all the payment integrations and more awesome features.', 'wpforms-lite' ) . '</p>
				<a href="' . esc_url( wpforms_admin_upgrade_link( 'builder-payments' ) ) . '" class="wpforms-btn wpforms-btn-orange wpforms-btn-md" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Upgrade to PRO', 'wpforms-lite' ) . '</a>
			</div>';

		} elseif ( empty( $payments_active ) ) {

			// Check for active payment addons. When no payment addons are
			// activated let the user know they need to install/activate an
			// addon to setup a payment.
			echo '<div class="wpforms-panel-content-section wpforms-panel-content-section-default">
				<div class="illustration illustration-payments"></div>
				<h5>' . esc_html__( 'Install Your Payment Integration', 'wpforms-lite' ) . '</h5>
				<p>' . sprintf(
					wp_kses(
						/* translators: %s - Addons page URL. */
						__( 'It seems you do not have any payment addons activated. You can head over to the <a href="%s">Addons page</a> to install and activate the addon for your payment service.', 'wpforms-lite' ),
						[
							'a' => [
								'href' => [],
							],
						]
					),
					esc_url( admin_url( 'admin.php?page=wpforms-addons' ) )
				) .
				'</p>
			</div>';

		} else {

			// Everything is good - display default instructions.
			echo '<div class="wpforms-panel-content-section wpforms-panel-content-section-default">
				<div class="illustration illustration-payments"></div>
				<h5>' . esc_html__( 'Install Your Payment Integration', 'wpforms-lite' ) . '</h5>
				<p>' . esc_html__( 'It seems you don\'t have any payment addons activated. Click one of the available addons and start accepting payments today!', 'wpforms-lite' ) . '</p>
			</div>';
		}

		do_action( 'wpforms_payments_panel_content', $this->form );
	}
}
new WPForms_Builder_Panel_Payments();
