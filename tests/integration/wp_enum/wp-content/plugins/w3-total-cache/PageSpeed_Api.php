<?php
/**
 * File: PageSpeed_Api.php
 *
 * Controls Google OAuth2.0 requests both for authentication and queries against the PageSpeed API.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

/**
 * PageSpeed API.
 *
 * @since 2.3.0
 */
class PageSpeed_Api {
	/**
	 * Config.
	 *
	 * @var object
	 */
	private $config;

	/**
	 * W3TCG_Google_Client.
	 *
	 * @var object
	 */
	public $client;

	/**
	 * W3TC Google Client JSON. Overwritten by W3TC_GOOGLE_CLIENT_JSON constant.
	 *
	 * @var string
	 */
	private $google_client_json = '{"web":{"client_id":"887173527583-mvtpm465985h8pokb3os715s9s3emv78.apps.googleusercontent.com","project_id":"w3tc-testing","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"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","redirect_uris":["google/authorize-in/","google/authorize-out/","google/update-token/","google/get-token/"]}}';

	/**
	 * W3TC API server base URL. Overwritten by W3TC_API2_URL constant.
	 *
	 * @var string
	 */
	private $w3tc_api_base_url = 'https://api2.w3-edge.com';

	/**
	 * Retry Attemps. Overwritten by W3TC_PAGESPEED_MAX_ATTEMPTS constant.
	 *
	 * @var string
	 */
	private $retry_attempts = 4;

	/**
	 * Google PageSpeed API URL. Overwritten by W3TC_PAGESPEED_API_URL constant.
	 *
	 * @var string
	 */
	private $pagespeed_api_base_url = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';

	/**
	 * PageSpeed API constructor.
	 *
	 * @since 2.3.0
	 *
	 * @param string $access_token_json API access token JSON.
	 */
	public function __construct( $access_token_json = null ) {
		$this->config = Dispatcher::config();
		$this->client = new \W3TCG_Google_Client();
		$this->client->setApplicationName( 'W3TC PageSpeed Analyzer' );
		$this->client->setAuthConfig( $this->get_client_json() );
		$this->client->setRedirectUri( $this->get_w3tc_api_url( 'google/authorize-out/' ) );
		$this->client->addScope( 'openid' );
		$this->client->setAccessType( 'offline' );
		$this->client->setApprovalPrompt( 'force' );
		$this->client->setDefer( true );

		if ( ! empty( $access_token_json ) ) {
			$this->client->setAccessToken( $access_token_json );
			$this->maybe_refresh_token();
		}
	}
	/**
	 * Run PageSpeed API.
	 *
	 * @since 2.3.0
	 *
	 * @return void
	 */
	public function run() {
		add_action( 'admin_notices', array( $this, 'authorize_notice' ) );
	}
	/**
	 * Fully analyze URL via PageSpeed API.
	 *
	 * @since 2.3.0
	 *
	 * @param string $url URL to analyze via PageSpeed API.
	 *
	 * @return array
	 */
	public function analyze( $url ) {
		$mobile  = $this->analyze_strategy( $url, 'mobile' );
		$desktop = $this->analyze_strategy( $url, 'desktop' );
		return array(
			'mobile'   => $mobile,
			'desktop'  => $desktop,
			'test_url' => Util_Environment::url_format(
				$this->get_pagespeed_url(),
				array( 'url' => $url )
			),
		);
	}

	/**
	 * Analyze URL via PageSpeed API using strategy.
	 *
	 * @since 2.3.0
	 *
	 * @param string $url URL to analyze.
	 * @param string $strategy Strategy to use desktop/mobile.
	 *
	 * @return array
	 */
	public function analyze_strategy( $url, $strategy ) {
		$data = $this->process_request(
			array(
				'url'      => $url,
				'category' => 'performance',
				'strategy' => $strategy,
			)
		);

		if ( ! empty( Util_PageSpeed::get_value_recursive( $data, array( 'error', 'code' ) ) ) ) {
			return array(
				'error' => array(
					'code'    => Util_PageSpeed::get_value_recursive( $data, array( 'error', 'code' ) ),
					'message' => Util_PageSpeed::get_value_recursive( $data, array( 'error', 'message' ) ),
				),
			);
		}

		return array_merge_recursive(
			PageSpeed_Data::prepare_pagespeed_data( $data ),
			PageSpeed_Instructions::get_pagespeed_instructions()
		);
	}

	/**
	 * Make API request.
	 *
	 * @since 2.3.0
	 *
	 * @param string $query API request query.
	 *
	 * @return array
	 */
	public function process_request( $query ) {
		$access_token_json = $this->client->getAccessToken();

		if ( empty( $access_token_json ) ) {
			return array(
				'error' => array(
					'code'    => 403,
					'message' => __( 'Missing Google access token.', 'w3-total-cache' ),
				),
			);
		}

		$access_token = json_decode( $access_token_json );

		$request = Util_Environment::url_format(
			$this->get_pagespeed_url(),
			array_merge(
				$query,
				array(
					'quotaUser'    => Util_Http::generate_site_id(),
					'access_token' => $access_token->access_token,
				)
			)
		);

		// Attempt the request up to x times with an increasing delay between each attempt. Uses W3TC_PAGESPEED_MAX_ATTEMPTS constant if defined.
		$attempts = 0;

		while ( ++$attempts <= $this->get_max_attempts() ) {
			try {
				$response = wp_remote_get(
					$request,
					array(
						'timeout' => 60,
					)
				);

				if ( ! is_wp_error( $response ) && 200 === $response['response']['code'] ) {
					break;
				}
			} catch ( \Exception $e ) {
				if ( $attempts >= $this->get_max_attempts() ) {
					return array(
						'error' => array(
							'code'    => 500,
							'message' => $e->getMessage(),
						),
					);
				}
			}

			// Sleep for a cumulative .5 seconds each attempt.
			usleep( $attempts * 500000 );
		};

		if ( isset( $response['response']['code'] ) && 200 !== $response['response']['code'] ) {
			// Google PageSpeed Insights sometimes will return a 500 and message body with details so we still grab the body response.
			$decoded_body = json_decode( wp_remote_retrieve_body( $response ), true );
			return array(
				'error' => array(
					'code'    => $response['response']['code'],
					'message' => ( ! empty( $decoded_body['error']['message'] ) ? $decoded_body['error']['message'] : $response['response']['message'] ),
				),
			);
		}

		return json_decode( wp_remote_retrieve_body( $response ), true );
	}

	/**
	 * Checks if the Google access token is expired and attempts to refresh.
	 *
	 * @since 2.3.0
	 *
	 * @return void
	 */
	public function maybe_refresh_token() {
		if ( $this->client->isAccessTokenExpired() && ! empty( $this->config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' ) ) ) {
			$this->refresh_token();
		}
	}

	/**
	 * Refreshes the Google access token if a valid refresh token is defined.
	 *
	 * @return string
	 */
	public function refresh_token() {
		$initial_refresh_token = $this->client->getRefreshToken();
		if ( empty( $initial_refresh_token ) ) {
			$initial_refresh_token_json = $this->get_refresh_token( Util_Http::generate_site_id(), $this->config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' ) );
			$initial_refresh_token      = json_decode( $initial_refresh_token_json );
			if ( ! empty( $initial_refresh_token->error ) ) {
				$refresh_url   = $this->get_w3tc_api_url( 'google/get-token' ) . '/' . Util_Http::generate_site_id() . '/' . $this->config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' );
				$error_code    = ! empty( $initial_refresh_token->error->code ) ? $initial_refresh_token->error->code : 'N/A';
				$error_message = ! empty( $initial_refresh_token->error->message ) ? $initial_refresh_token->error->message : 'N/A';
				return wp_json_encode(
					array(
						'error' => '<p><strong>' . esc_html__( 'API request error!', 'w3-total-cache' ) . '</strong></p>
							<p>' . esc_html__( 'Refresh URL : ', 'w3-total-cache' ) . $refresh_url . '</p>
							<p>' . esc_html__( 'Response Code : ', 'w3-total-cache' ) . $error_code . '</p>
							<p>' . esc_html__( 'Response Message : ', 'w3-total-cache' ) . $error_message . '</p>',
					)
				);
			}
		}

		try {
			$this->client->refreshToken( $initial_refresh_token->refresh_token );
		} catch ( \Exception $e ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 500,
						'message' => $e->getMessage(),
					),
				)
			);
		}

		$new_access_token = json_decode( $this->client->getAccessToken() );

		if ( ! empty( $new_access_token->refresh_token ) ) {
			$new_refresh_token = $new_access_token->refresh_token;
			unset( $new_access_token->refresh_token );

			$request = Util_Environment::url_format(
				$this->get_w3tc_api_url( 'google/update-token' ),
				array(
					'site_id'            => Util_Http::generate_site_id(),
					'w3tc_pagespeed_key' => $this->config->get_string( 'widget.pagespeed.w3tc_pagespeed_key' ),
					'refresh_token'      => $new_refresh_token,
				)
			);

			$response = wp_remote_get(
				$request,
				array(
					'timeout' => 60,
				)
			);

			if ( is_wp_error( $response ) ) {
				return wp_json_encode(
					array(
						'error' => array(
							'code'    => $response->get_error_code(),
							'message' => $response->get_error_message(),
						),
					)
				);
			} elseif ( isset( $response['error']['code'] ) && 200 !== $response['error']['code'] ) {
				if ( 'update-token-missing-site-id' === $response['error']['id'] ) {
					$message = __( 'No site ID provided for Google access record update!', 'w3-total-cache' );
				} elseif ( 'update-token-missing-w3tc-pagespeed-key' === $response['error']['id'] ) {
					$message = __( 'No W3 key provided for Google access record update!', 'w3-total-cache' );
				} elseif ( 'update-token-missing-refresh-token' === $response['error']['id'] ) {
					$message = __( 'No refresh token provided for Google access record update!', 'w3-total-cache' );
				} elseif ( 'update-token-not-found' === $response['error']['id'] ) {
					$message = __( 'No matching Google access record found for W3 key!', 'w3-total-cache' );
				}

				return wp_json_encode(
					array(
						'error' => array(
							'code'    => $response['error']['code'],
							'message' => $message,
						),
					)
				);
			}
		}

		$this->config->set( 'widget.pagespeed.access_token', wp_json_encode( $new_access_token ) );
		$this->config->save();

		return wp_json_encode( array( 'access_key' => $new_access_token ) );
	}

	/**
	 * Creates new Google access token from authorize request response.
	 *
	 * @since 2.3.0
	 *
	 * @param string $gacode             New Google access authentication code.
	 * @param string $w3tc_pagespeed_key W3 API access key.
	 *
	 * @return JSON
	 */
	public function process_authorization_response( $gacode, $w3tc_pagespeed_key ) {
		if ( empty( $gacode ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 409,
						'message' => __( 'Missing/invalid Google access authentication code.', 'w3-total-cache' ),
					),
				)
			);
		} elseif ( empty( $w3tc_pagespeed_key ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 409,
						'message' => __( 'Missing/invalid W3 API key.', 'w3-total-cache' ),
					),
				)
			);
		}

		try {
			$this->client->authenticate( $gacode );
		} catch ( \Exception $e ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 500,
						'message' => $e->getMessage(),
					),
				)
			);
		}

		$access_token_json = $this->client->getAccessToken();

		if ( empty( $access_token_json ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 409,
						'message' => __( 'Missing/invalid Google access token JSON setting after authentication.', 'w3-total-cache' ),
					),
				)
			);
		}

		$access_token = ( ! empty( $access_token_json ) ? json_decode( $access_token_json ) : '' );

		$request = Util_Environment::url_format(
			$this->get_w3tc_api_url( 'google/update-token' ),
			array(
				'site_id'            => Util_Http::generate_site_id(),
				'w3tc_pagespeed_key' => $w3tc_pagespeed_key,
				'refresh_token'      => $access_token->refresh_token,
			)
		);

		$response = wp_remote_get(
			$request,
			array(
				'timeout' => 60,
			)
		);

		if ( is_wp_error( $response ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => $response->get_error_code(),
						'message' => $response->get_error_message(),
					),
				)
			);
		} elseif ( isset( $response['error']['code'] ) && 200 !== $response['error']['code'] ) {
			if ( 'update-token-missing-site-id' === $response['error']['id'] ) {
				$message = __( 'No site ID provided for Google access record update!', 'w3-total-cache' );
			} elseif ( 'update-token-missing-w3tc-pagespeed-key' === $response['error']['id'] ) {
				$message = __( 'No W3 key provided for Google access record update!', 'w3-total-cache' );
			} elseif ( 'update-token-missing-refresh-token' === $response['error']['id'] ) {
				$message = __( 'No refresh token provided for Google access record update!', 'w3-total-cache' );
			} elseif ( 'update-token-not-found' === $response['error']['id'] ) {
				$message = __( 'No matching Google access record found for W3 key!', 'w3-total-cache' );
			}
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => $response['error']['code'],
						'message' => $message,
					),
				)
			);
		}

		unset( $access_token->refresh_token );

		$this->config->set( 'widget.pagespeed.access_token', wp_json_encode( $access_token ) );
		$this->config->set( 'widget.pagespeed.w3tc_pagespeed_key', $w3tc_pagespeed_key );
		$this->config->save();

		return wp_json_encode( array( 'refresh_token' => $access_token ) );
	}

	/**
	 * Fetches Google refresh token from W3 API server.
	 *
	 * @since 2.3.0
	 *
	 * @param string $site_id            Site ID.
	 * @param string $w3tc_pagespeed_key W3 API access key.
	 *
	 * @return string
	 */
	public function get_refresh_token( $site_id, $w3tc_pagespeed_key ) {
		if ( empty( $site_id ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 409,
						'message' => __( 'Missing/invalid Site ID.', 'w3-total-cache' ),
					),
				)
			);
		} elseif ( empty( $w3tc_pagespeed_key ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => 409,
						'message' => __( 'Missing/invalid W3 API key.', 'w3-total-cache' ),
					),
				)
			);
		}

		$request = $this->get_w3tc_api_url( 'google/get-token' ) . '/' . $site_id . '/' . $w3tc_pagespeed_key;

		$response = wp_remote_get(
			$request,
			array(
				'timeout' => 60,
			)
		);

		if ( is_wp_error( $response ) ) {
			return wp_json_encode(
				array(
					'error' => array(
						'code'    => $response->get_error_code(),
						'message' => $response->get_error_message(),
					),
				)
			);
		} elseif ( isset( $response['error']['code'] ) && 200 !== $response['error']['code'] ) {
			if ( 'get-token-missing-site-id' === $response['error']['id'] ) {
				$message = __( 'No site ID provided for Google access record update!', 'w3-total-cache' );
			} elseif ( 'get-token-missing-w3tc-pagespeed-key' === $response['error']['id'] ) {
				$message = __( 'No W3 key provided for Google access record update!', 'w3-total-cache' );
			} elseif ( 'get-token-not-found' === $response['error']['id'] ) {
				$message = __( 'No matching Google access record found for W3 key!', 'w3-total-cache' );
			} elseif ( 'get-token-bad-record' === $response['error']['id'] ) {
				$message = __( 'Matching Google access record found but the refresh token value is blank!', 'w3-total-cache' );
			}

			return wp_json_encode(
				array(
					'error' => array(
						'code'    => $response['error']['code'],
						'message' => $message,
					),
				)
			);
		}

		// Response body should contain a JSON format string.
		return wp_remote_retrieve_body( $response );
	}

	/**
	 * Get Google Client JSON config.
	 *
	 * @since 2.3.0
	 *
	 * @return string
	 */
	public function get_client_json() {
		$client_json = defined( 'W3TC_GOOGLE_CLIENT_JSON' ) && W3TC_GOOGLE_CLIENT_JSON ? W3TC_GOOGLE_CLIENT_JSON : $this->google_client_json;
		$client      = json_decode( $client_json );
		foreach ( $client->web->redirect_uris as $redirect_uri_key => $redirect_uri_value ) {
			$client->web->redirect_uris[ $redirect_uri_key ] = $this->get_w3tc_api_url( $redirect_uri_value );
		}
		return wp_json_encode( $client );
	}

	/**
	 * Get W3TC PageSpeed API max attempts.
	 *
	 * @since 2.3.0
	 *
	 * @return int
	 */
	public function get_max_attempts() {
		return defined( 'W3TC_PAGESPEED_MAX_ATTEMPTS' ) && W3TC_PAGESPEED_MAX_ATTEMPTS ? W3TC_PAGESPEED_MAX_ATTEMPTS : $this->retry_attempts;
	}

	/**
	 * Get Google PageSpeed API URL.
	 *
	 * @since 2.3.0
	 *
	 * @return string
	 */
	public function get_pagespeed_url() {
		return defined( 'W3TC_PAGESPEED_API_URL' ) && W3TC_PAGESPEED_API_URL ? W3TC_PAGESPEED_API_URL : $this->pagespeed_api_base_url;
	}

	/**
	 * Get W3TC API server URL target.
	 *
	 * @since 2.3.0
	 *
	 * @param string $target API target URI.
	 *
	 * @return string
	 */
	public function get_w3tc_api_url( $target ) {
		return defined( 'W3TC_API2_URL' ) && W3TC_API2_URL ?
			trailingslashit( W3TC_API2_URL ) . $target :
			trailingslashit( $this->w3tc_api_base_url ) . $target;
	}

	/**
	 * PageSpeed authorize admin notice.
	 *
	 * @since 2.3.0
	 */
	public function authorize_notice() {
		if ( current_user_can( 'manage_options' ) && get_option( 'w3tcps_authorize_success' ) ) {
			echo '<div class="updated is-dismissible"><p>' . esc_html( get_option( 'w3tcps_authorize_success' ) ) . '</p></div>';
			delete_option( 'w3tcps_authorize_success ' );
		} elseif ( current_user_can( 'manage_options' ) && get_option( 'w3tcps_authorize_fail' ) ) {
			echo '<div class="error is-dismissible"><p>' . esc_html( get_option( 'w3tcps_authorize_fail' ) ) . '</p><p>' . wp_kses( get_option( 'w3tcps_authorize_fail_message' ), Util_PageSpeed::get_allowed_tags() ) . '</p></div>';
			delete_option( 'w3tcps_authorize_fail ' );
			delete_option( 'w3tcps_authorize_fail_message ' );
		}
	}

	/**
	 * Reset authentication.
	 *
	 * @since 2.3.0
	 */
	public function reset() {
		$access_token = $this->client->getAccessToken();
		$this->client->revokeToken( $access_token );
		$this->config->set( 'widget.pagespeed.access_token', '' );
		$this->config->set( 'widget.pagespeed.w3key', '' );
		$this->config->save();
	}
}
