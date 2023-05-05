<?php

if ( ! class_exists( 'WPCF7_Service_OAuth2' ) ) {
	return;
}

class WPCF7_ConstantContact extends WPCF7_Service_OAuth2 {

	const service_name = 'constant_contact';

	const authorization_endpoint
		= 'https://authz.constantcontact.com/oauth2/default/v1/authorize';

	const token_endpoint
		= 'https://authz.constantcontact.com/oauth2/default/v1/token';

	private static $instance;
	protected $contact_lists = array();

	public static function get_instance() {
		if ( empty( self::$instance ) ) {
			self::$instance = new self;
		}

		return self::$instance;
	}

	private function __construct() {
		$this->authorization_endpoint = self::authorization_endpoint;
		$this->token_endpoint = self::token_endpoint;

		$option = (array) WPCF7::get_option( self::service_name );

		if ( isset( $option['client_id'] ) ) {
			$this->client_id = $option['client_id'];
		}

		if ( isset( $option['client_secret'] ) ) {
			$this->client_secret = $option['client_secret'];
		}

		if ( isset( $option['access_token'] ) ) {
			$this->access_token = $option['access_token'];
		}

		if ( isset( $option['refresh_token'] ) ) {
			$this->refresh_token = $option['refresh_token'];
		}

		if ( $this->is_active() ) {
			if ( isset( $option['contact_lists'] ) ) {
				$this->contact_lists = $option['contact_lists'];
			}
		}

		add_action( 'wpcf7_admin_init', array( $this, 'auth_redirect' ) );
	}

	public function auth_redirect() {
		$auth = isset( $_GET['auth'] ) ? trim( $_GET['auth'] ) : '';

		if ( self::service_name === $auth
		and current_user_can( 'wpcf7_manage_integration' ) ) {
			$redirect_to = add_query_arg(
				array(
					'service' => self::service_name,
					'action' => 'auth_redirect',
					'code' => isset( $_GET['code'] ) ? trim( $_GET['code'] ) : '',
					'state' => isset( $_GET['state'] ) ? trim( $_GET['state'] ) : '',
				),
				menu_page_url( 'wpcf7-integration', false )
			);

			wp_safe_redirect( $redirect_to );
			exit();
		}
	}

	protected function save_data() {
		$option = array_merge(
			(array) WPCF7::get_option( self::service_name ),
			array(
				'client_id' => $this->client_id,
				'client_secret' => $this->client_secret,
				'access_token' => $this->access_token,
				'refresh_token' => $this->refresh_token,
				'contact_lists' => $this->contact_lists,
			)
		);

		WPCF7::update_option( self::service_name, $option );
	}

	protected function reset_data() {
		$this->client_id = '';
		$this->client_secret = '';
		$this->access_token = '';
		$this->refresh_token = '';
		$this->contact_lists = array();

		$this->save_data();
	}

	public function get_title() {
		return __( 'Constant Contact', 'contact-form-7' );
	}

	public function get_categories() {
		return array( 'email_marketing' );
	}

	public function icon() {
	}

	public function link() {
		echo sprintf( '<a href="%1$s">%2$s</a>',
			'https://constant-contact.evyy.net/c/1293104/205991/3411',
			'constantcontact.com'
		);
	}

	protected function get_redirect_uri() {
		return admin_url( '/?auth=' . self::service_name );
	}

	protected function menu_page_url( $args = '' ) {
		$args = wp_parse_args( $args, array() );

		$url = menu_page_url( 'wpcf7-integration', false );
		$url = add_query_arg( array( 'service' => self::service_name ), $url );

		if ( ! empty( $args ) ) {
			$url = add_query_arg( $args, $url );
		}

		return $url;
	}

	public function load( $action = '' ) {
		if ( 'auth_redirect' == $action ) {
			$code = isset( $_GET['code'] ) ? urldecode( $_GET['code'] ) : '';
			$state = isset( $_GET['state'] ) ? urldecode( $_GET['state'] ) : '';

			if ( $code and $state
			and wpcf7_verify_nonce( $state, 'wpcf7_constant_contact_authorize' ) ) {
				$response = $this->request_token( $code );
			}

			if ( ! empty( $this->access_token ) ) {
				$message = 'success';
			} else {
				$message = 'failed';
			}

			wp_safe_redirect( $this->menu_page_url(
				array(
					'action' => 'setup',
					'message' => $message,
				)
			) );

			exit();
		}

		if ( 'setup' == $action and 'POST' == $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'wpcf7-constant-contact-setup' );

			if ( ! empty( $_POST['reset'] ) ) {
				$this->reset_data();
			} else {
				$this->client_id = isset( $_POST['client_id'] )
					? trim( $_POST['client_id'] ) : '';

				$this->client_secret = isset( $_POST['client_secret'] )
					? trim( $_POST['client_secret'] ) : '';

				$this->save_data();
				$this->authorize( 'contact_data offline_access' );
			}

			wp_safe_redirect( $this->menu_page_url( 'action=setup' ) );
			exit();
		}
	}

	protected function authorize( $scope = '' ) {
		$endpoint = add_query_arg(
			array_map( 'urlencode', array(
				'response_type' => 'code',
				'client_id' => $this->client_id,
				'redirect_uri' => $this->get_redirect_uri(),
				'scope' => $scope,
				'state' => wpcf7_create_nonce( 'wpcf7_constant_contact_authorize' ),
			) ),
			$this->authorization_endpoint
		);

		if ( wp_redirect( sanitize_url( $endpoint ) ) ) {
			exit();
		}
	}

	public function email_exists( $email ) {
		$endpoint = add_query_arg(
			array(
				'email' => $email,
				'status' => 'all',
			),
			'https://api.cc.email/v3/contacts'
		);

		$request = array(
			'method' => 'GET',
			'headers' => array(
				'Accept' => 'application/json',
				'Content-Type' => 'application/json; charset=utf-8',
			),
		);

		$response = $this->remote_request( $endpoint, $request );

		if ( 400 <= (int) wp_remote_retrieve_response_code( $response ) ) {
			if ( WP_DEBUG ) {
				$this->log( $endpoint, $request, $response );
			}

			return false;
		}

		$response_body = wp_remote_retrieve_body( $response );

		if ( empty( $response_body ) ) {
			return false;
		}

		$response_body = json_decode( $response_body, true );

		return ! empty( $response_body['contacts'] );
	}

	public function create_contact( $properties ) {
		$endpoint = 'https://api.cc.email/v3/contacts';

		$request = array(
			'method' => 'POST',
			'headers' => array(
				'Accept' => 'application/json',
				'Content-Type' => 'application/json; charset=utf-8',
			),
			'body' => json_encode( $properties ),
		);

		$response = $this->remote_request( $endpoint, $request );

		if ( 400 <= (int) wp_remote_retrieve_response_code( $response ) ) {
			if ( WP_DEBUG ) {
				$this->log( $endpoint, $request, $response );
			}

			return false;
		}
	}

	public function get_contact_lists() {
		$endpoint = 'https://api.cc.email/v3/contact_lists';

		$request = array(
			'method' => 'GET',
			'headers' => array(
				'Accept' => 'application/json',
				'Content-Type' => 'application/json; charset=utf-8',
			),
		);

		$response = $this->remote_request( $endpoint, $request );

		if ( 400 <= (int) wp_remote_retrieve_response_code( $response ) ) {
			if ( WP_DEBUG ) {
				$this->log( $endpoint, $request, $response );
			}

			return false;
		}

		$response_body = wp_remote_retrieve_body( $response );

		if ( empty( $response_body ) ) {
			return false;
		}

		$response_body = json_decode( $response_body, true );

		if ( ! empty( $response_body['lists'] ) ) {
			return (array) $response_body['lists'];
		} else {
			return array();
		}
	}

	public function update_contact_lists( $selection = array() ) {
		$contact_lists = array();
		$contact_lists_on_api = $this->get_contact_lists();

		if ( false !== $contact_lists_on_api ) {
			foreach ( (array) $contact_lists_on_api as $list ) {
				if ( isset( $list['list_id'] ) ) {
					$list_id = trim( $list['list_id'] );
				} else {
					continue;
				}

				if ( isset( $this->contact_lists[$list_id]['selected'] ) ) {
					$list['selected'] = $this->contact_lists[$list_id]['selected'];
				} else {
					$list['selected'] = array();
				}

				$contact_lists[$list_id] = $list;
			}
		} else {
			$contact_lists = $this->contact_lists;
		}

		foreach ( (array) $selection as $key => $ids_or_names ) {
			foreach( $contact_lists as $list_id => $list ) {
				if ( in_array( $list['list_id'], (array) $ids_or_names, true )
				or in_array( $list['name'], (array) $ids_or_names, true ) ) {
					$contact_lists[$list_id]['selected'][$key] = true;
				} else {
					unset( $contact_lists[$list_id]['selected'][$key] );
				}
			}
		}

		$this->contact_lists = $contact_lists;

		if ( $selection ) {
			$this->save_data();
		}

		return $this->contact_lists;
	}

	public function admin_notice( $message = '' ) {
		switch ( $message ) {
			case 'success':
				echo sprintf(
					'<div class="notice notice-success"><p>%s</p></div>',
					esc_html( __( "Connection established.", 'contact-form-7' ) )
				);
				break;
			case 'failed':
				echo sprintf(
					'<div class="notice notice-error"><p><strong>%1$s</strong>: %2$s</p></div>',
					esc_html( __( "Error", 'contact-form-7' ) ),
					esc_html( __( "Failed to establish connection. Please double-check your configuration.", 'contact-form-7' ) )
				);
				break;
			case 'updated':
				echo sprintf(
					'<div class="notice notice-success"><p>%s</p></div>',
					esc_html( __( "Configuration updated.", 'contact-form-7' ) )
				);
				break;
		}
	}

	public function display( $action = '' ) {
		echo sprintf(
			'<p>%s</p>',
			esc_html( __( "The Constant Contact integration module allows you to send contact data collected through your contact forms to the Constant Contact API. You can create reliable email subscription services in a few easy steps.", 'contact-form-7' ) )
		);

		echo sprintf(
			'<p><strong>%s</strong></p>',
			wpcf7_link(
				__( 'https://contactform7.com/constant-contact-integration/', 'contact-form-7' ),
				__( 'Constant Contact integration', 'contact-form-7' )
			)
		);

		if ( $this->is_active() ) {
			echo sprintf(
				'<p class="dashicons-before dashicons-yes">%s</p>',
				esc_html( __( "This site is connected to the Constant Contact API.", 'contact-form-7' ) )
			);
		}

		if ( 'setup' == $action ) {
			$this->display_setup();
		} else {
			echo sprintf(
				'<p><a href="%1$s" class="button">%2$s</a></p>',
				esc_url( $this->menu_page_url( 'action=setup' ) ),
				esc_html( __( 'Setup Integration', 'contact-form-7' ) )
			);
		}
	}

	private function display_setup() {
?>
<form method="post" action="<?php echo esc_url( $this->menu_page_url( 'action=setup' ) ); ?>">
<?php wp_nonce_field( 'wpcf7-constant-contact-setup' ); ?>
<table class="form-table">
<tbody>
<tr>
	<th scope="row"><label for="client_id"><?php echo esc_html( __( 'API Key', 'contact-form-7' ) ); ?></label></th>
	<td><?php
		if ( $this->is_active() ) {
			echo esc_html( $this->client_id );
			echo sprintf(
				'<input type="hidden" value="%1$s" id="client_id" name="client_id" />',
				esc_attr( $this->client_id )
			);
		} else {
			echo sprintf(
				'<input type="text" aria-required="true" value="%1$s" id="client_id" name="client_id" class="regular-text code" />',
				esc_attr( $this->client_id )
			);
		}
	?></td>
</tr>
<tr>
	<th scope="row"><label for="client_secret"><?php echo esc_html( __( 'App Secret', 'contact-form-7' ) ); ?></label></th>
	<td><?php
		if ( $this->is_active() ) {
			echo esc_html( wpcf7_mask_password( $this->client_secret, 4, 4 ) );
			echo sprintf(
				'<input type="hidden" value="%1$s" id="client_secret" name="client_secret" />',
				esc_attr( $this->client_secret )
			);
		} else {
			echo sprintf(
				'<input type="text" aria-required="true" value="%1$s" id="client_secret" name="client_secret" class="regular-text code" />',
				esc_attr( $this->client_secret )
			);
		}
	?></td>
</tr>
<tr>
	<th scope="row"><label for="redirect_uri"><?php echo esc_html( __( 'Redirect URI', 'contact-form-7' ) ); ?></label></th>
	<td><?php
		echo sprintf(
			'<input type="text" value="%1$s" id="redirect_uri" name="redirect_uri" class="large-text code" readonly="readonly" onfocus="this.select();" style="font-size: 11px;" />',
			$this->get_redirect_uri()
		);
	?>
	<p class="description"><?php echo esc_html( __( "Set this URL as the redirect URI.", 'contact-form-7' ) ); ?></p>
	</td>
</tr>
</tbody>
</table>
<?php
		if ( $this->is_active() ) {
			submit_button(
				_x( 'Reset Keys', 'API keys', 'contact-form-7' ),
				'small', 'reset'
			);
		} else {
			submit_button(
				__( 'Connect to the Constant Contact API', 'contact-form-7' )
			);
		}
?>
</form>
<?php
	}

}
