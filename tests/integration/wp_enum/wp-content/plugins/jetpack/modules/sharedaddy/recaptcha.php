<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Google reCAPTCHA utilities, for use in the sharing feature.
 *
 * @package automattic/jetpack
 */

/**
 * Class that handles reCAPTCHA.
 *
 * @deprecated 11.0
 */
class Jetpack_ReCaptcha {

	/**
	 * URL to which requests are POSTed.
	 *
	 * @const string
	 */
	const VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify';

	/**
	 * Site key to use in HTML code.
	 *
	 * @var string
	 */
	private $site_key;

	/**
	 * Shared secret for the site.
	 *
	 * @var string
	 */
	private $secret_key;

	/**
	 * Config for reCAPTCHA instance.
	 *
	 * @var array
	 */
	private $config;

	/**
	 * Error codes returned from reCAPTCHA API.
	 *
	 * @see https://developers.google.com/recaptcha/docs/verify
	 *
	 * @var array
	 */
	private $error_codes;

	/**
	 * Create a configured instance to use the reCAPTCHA service.
	 *
	 * @param string $site_key   Site key to use in HTML code.
	 * @param string $secret_key Shared secret between site and reCAPTCHA server.
	 * @param array  $config     Config array to optionally configure reCAPTCHA instance.
	 */
	public function __construct( $site_key, $secret_key, $config = array() ) {
		$this->site_key   = $site_key;
		$this->secret_key = $secret_key;
		$this->config     = wp_parse_args( $config, $this->get_default_config() );

		$this->error_codes = array(
			'missing-input-secret'   => __( 'The secret parameter is missing', 'jetpack' ),
			'invalid-input-secret'   => __( 'The secret parameter is invalid or malformed', 'jetpack' ),
			'missing-input-response' => __( 'The response parameter is missing', 'jetpack' ),
			'invalid-input-response' => __( 'The response parameter is invalid or malformed', 'jetpack' ),
			'invalid-json'           => __( 'Invalid JSON', 'jetpack' ),
			'unexpected-response'    => __( 'Unexpected response', 'jetpack' ),
			'unexpected-hostname'    => __( 'Unexpected hostname', 'jetpack' ),
		);
	}

	/**
	 * Get default config for this reCAPTCHA instance.
	 *
	 * @return array Default config
	 */
	public function get_default_config() {
		return array(
			'language'       => get_locale(),
			'script_async'   => false,
			'script_defer'   => true,
			'script_lazy'    => false,
			'tag_class'      => 'g-recaptcha',
			'tag_attributes' => array(
				'theme'    => 'light',
				'type'     => 'image',
				'tabindex' => 0,
			),
		);
	}

	/**
	 * Calls the reCAPTCHA siteverify API to verify whether the user passes
	 * CAPTCHA test.
	 *
	 * @param string $response  The value of 'g-recaptcha-response' in the submitted
	 *                          form.
	 * @param string $remote_ip The end user's IP address.
	 *
	 * @return bool|WP_Error Returns true if verified. Otherwise WP_Error is returned.
	 */
	public function verify( $response, $remote_ip ) {
		// No need make a request if response is empty.
		if ( empty( $response ) ) {
			return new WP_Error( 'missing-input-response', $this->error_codes['missing-input-response'], 400 );
		}

		$resp = wp_remote_post( self::VERIFY_URL, $this->get_verify_request_params( $response, $remote_ip ) );
		if ( is_wp_error( $resp ) ) {
			return $resp;
		}

		$resp_decoded = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( ! $resp_decoded ) {
			return new WP_Error( 'invalid-json', $this->error_codes['invalid-json'], 400 );
		}

		// Default error code and message.
		$error_code    = 'unexpected-response';
		$error_message = $this->error_codes['unexpected-response'];

		// Use the first error code if exists.
		if ( isset( $resp_decoded['error-codes'] ) && is_array( $resp_decoded['error-codes'] ) ) {
			if ( isset( $resp_decoded['error-codes'][0] ) && isset( $this->error_codes[ $resp_decoded['error-codes'][0] ] ) ) {
				$error_message = $this->error_codes[ $resp_decoded['error-codes'][0] ];
				$error_code    = $resp_decoded['error-codes'][0];
			}
		}

		if ( ! isset( $resp_decoded['success'] ) ) {
			return new WP_Error( $error_code, $error_message );
		}

		if ( true !== $resp_decoded['success'] ) {
			return new WP_Error( $error_code, $error_message );
		}
		// Validate the hostname matches expected source
		if ( isset( $resp_decoded['hostname'] ) ) {
			$url = wp_parse_url( get_home_url() );

			/**
			 * Allow other valid hostnames.
			 *
			 * This can be useful in cases where the token hostname is expected to be
			 * different from the get_home_url (ex. AMP recaptcha token contains a different hostname)
			 *
			 * @module sharedaddy
			 *
			 * @since 9.1.0
			 *
			 * @param array [ $url['host'] ] List of the valid hostnames to check against.
			 */
			$valid_hostnames = apply_filters( 'jetpack_recaptcha_valid_hostnames', array( $url['host'] ) );

			if ( ! in_array( $resp_decoded['hostname'], $valid_hostnames, true ) ) {
				return new WP_Error( 'unexpected-host', $this->error_codes['unexpected-hostname'] );
			}
		}

		return true;
	}

	/**
	 * Get siteverify request parameters.
	 *
	 * @param string $response  The value of 'g-recaptcha-response' in the submitted
	 *                          form.
	 * @param string $remote_ip The end user's IP address.
	 *
	 * @return array
	 */
	public function get_verify_request_params( $response, $remote_ip ) {
		return array(
			'body'      => array(
				'secret'   => $this->secret_key,
				'response' => $response,
				'remoteip' => $remote_ip,
			),
			'sslverify' => true,
		);
	}

	/**
	 * Get reCAPTCHA HTML to render.
	 *
	 * @return string
	 */
	public function get_recaptcha_html() {
		$url = sprintf(
			'https://www.google.com/recaptcha/api.js?hl=%s',
			rawurlencode( $this->config['language'] )
		);

		$html = sprintf(
			'
			<div
				class="%s"
				data-sitekey="%s"
				data-theme="%s"
				data-type="%s"
				data-tabindex="%s"
				data-lazy="%s"
				data-url="%s"></div>
			',
			esc_attr( $this->config['tag_class'] ),
			esc_attr( $this->site_key ),
			esc_attr( $this->config['tag_attributes']['theme'] ),
			esc_attr( $this->config['tag_attributes']['type'] ),
			esc_attr( $this->config['tag_attributes']['tabindex'] ),
			$this->config['script_lazy'] ? 'true' : 'false',
			esc_attr( $url )
		);

		if ( ! $this->config['script_lazy'] ) {
			$html = $html . sprintf(
				// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
				'<script src="%s"%s%s></script>
				',
				$url,
				$this->config['script_async'] && ! $this->config['script_defer'] ? ' async' : '',
				$this->config['script_defer'] ? ' defer' : ''
			);
		}

		return $html;
	}
}
