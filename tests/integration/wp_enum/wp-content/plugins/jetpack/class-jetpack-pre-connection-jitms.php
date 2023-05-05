<?php
/**
 * Jetpack's Pre-Connection JITMs class.
 *
 * @package jetpack
 */

use Automattic\Jetpack\Partner_Coupon as Jetpack_Partner_Coupon;
use Automattic\Jetpack\Redirect;

/**
 * Jetpack's Pre-Connection JITMs. These can be displayed with the JITM package.
 */
class Jetpack_Pre_Connection_JITMs {

	/**
	 * Returns all the pre-connection messages.
	 *
	 * @return array An array containing the pre-connection JITM messages.
	 */
	private function get_raw_messages() {
		$button_caption = __( 'Set up Jetpack', 'jetpack' );
		/* Translators: placeholders are links. */
		$media_description = __( 'Click on the <strong>Set up Jetpack</strong> button to agree to our <a href="%1$s" target="_blank" rel="noopener noreferrer">Terms of Service</a> and to <a href="%2$s" target="_blank" rel="noopener noreferrer">share details</a> with WordPress.com, and gain access to Site Accelerator.', 'jetpack' );
		/* Translators: placeholders are links. */
		$widgets_description = __( 'Click on the <strong>Set up Jetpack</strong> button to agree to our <a href="%1$s" target="_blank" rel="noopener noreferrer">Terms of Service</a> and to <a href="%2$s" target="_blank" rel="noopener noreferrer">share details</a> with WordPress.com, and gain access to great additional widgets.', 'jetpack' );
		/* Translators: placeholders are links. */
		$posts_description = __( 'Click on the <strong>Set up Jetpack</strong> button to agree to our <a href="%1$s" target="_blank" rel="noopener noreferrer">Terms of Service</a> and to <a href="%2$s" target="_blank" rel="noopener noreferrer">share details</a> with WordPress.com, and gain access to in-depth stats about your site.', 'jetpack' );

		$messages = array(
			array(
				'id'             => 'jpsetup-upload',
				'message_path'   => '/wp:upload:admin_notices/',
				'message'        => __( 'Do you want lightning-fast images?', 'jetpack' ),
				'description'    => $this->generate_description_with_tos( $media_description ),
				'button_caption' => $button_caption,
			),
			array(
				'id'             => 'jpsetup-widgets',
				'message_path'   => '/wp:widgets:admin_notices/',
				'message'        => __( 'Looking for even more widgets?', 'jetpack' ),
				'description'    => $this->generate_description_with_tos( $widgets_description ),
				'button_caption' => $button_caption,
			),
		);

		if ( wp_count_posts()->publish >= 5 ) {
			$messages[] = array(
				'id'             => 'jpsetup-posts',
				'message_path'   => '/wp:edit-post:admin_notices/',
				'message'        => __( 'Do you know which of these posts gets the most traffic?', 'jetpack' ),
				'description'    => $this->generate_description_with_tos( $posts_description ),
				'button_caption' => $button_caption,
			);
		}

		foreach ( $messages as $key => $message ) {
			/*
			 * Add Connect URL to each message, with from including jitm id.
			 */
			$jetpack_setup_url               = $this->generate_admin_url(
				array(
					'page' => 'jetpack#/setup',
					'from' => sprintf( 'pre-connection-jitm-%s', $message['id'] ),
				)
			);
			$messages[ $key ]['button_link'] = $jetpack_setup_url;
		}

		return $messages;
	}

	/**
	 * Generate a description text with links to ToS documents.
	 *
	 * Those messages must mention the ToS agreement message,
	 * but do not use the standard message defined in jetpack_render_tos_blurb.
	 * Instead, they use their own custom messages.
	 *
	 * @param string $description Description string with placeholders.
	 *
	 * @return string
	 */
	private function generate_description_with_tos( $description ) {
		return sprintf(
			wp_kses(
				$description,
				array(
					'a'      => array(
						'href'   => array(),
						'target' => array(),
						'rel'    => array(),
					),
					'strong' => true,
				)
			),
			esc_url( Redirect::get_url( 'wpcom-tos' ) ),
			esc_url( Redirect::get_url( 'jetpack-support-what-data-does-jetpack-sync' ) )
		);
	}

	/**
	 * Returns partnership related pre-connection messages.
	 *
	 * @since 10.4
	 *
	 * @return array An array containing the pre-connection JITM messages.
	 */
	private function maybe_get_raw_partnership_messages() {
		$partner_coupon = Jetpack_Partner_Coupon::get_coupon();

		if ( ! $partner_coupon ) {
			return array();
		}

		return array(
			array(
				'id'             => 'jpsetup-partner-coupon',
				'message_path'   => '/wp:(plugin-install|themes|update-core|upload|users|tools|options-general):admin_notices/',
				/* Translators: 1: Product name, 2: Partner name. */
				'message'        => sprintf( esc_html__( 'Get %1$s with your %2$s account', 'jetpack' ), $partner_coupon['product']['title'], $partner_coupon['partner']['name'] ),
				'description'    => $partner_coupon['product']['description'],
				'button_caption' => esc_html__( 'Redeem coupon', 'jetpack' ),
				'button_link'    => $this->generate_admin_url(
					array(
						'page' => 'jetpack#/dashboard',
						'from' => 'pre-connection-jitm--jpsetup-partner-coupon',
					)
				),
			),
		);
	}

	/**
	 * Adds the input query arguments to the admin url.
	 *
	 * @param array $args The query arguments.
	 *
	 * @return string The admin url.
	 */
	private function generate_admin_url( $args ) {
		$url = add_query_arg( $args, admin_url( 'admin.php' ) );
		return $url;
	}

	/**
	 * Add the Jetpack pre-connection JITMs to the list of pre-connection JITM messages.
	 *
	 * @param array $pre_connection_messages An array of pre-connection JITMs.
	 *
	 * @return array The array of pre-connection JITMs.
	 */
	public function add_pre_connection_jitms( $pre_connection_messages ) {
		$jetpack_messages = array_merge( $this->get_raw_messages(), $this->maybe_get_raw_partnership_messages() );

		if ( ! is_array( $pre_connection_messages ) ) {
			// The incoming messages aren't an array, so just return Jetpack's messages.
			return $jetpack_messages;
		}

		return array_merge( $pre_connection_messages, $jetpack_messages );
	}
}
