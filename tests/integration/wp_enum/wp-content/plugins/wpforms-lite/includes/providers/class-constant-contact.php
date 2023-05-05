<?php

/**
 * Constant Contact integration.
 *
 * @since 1.3.6
 */
class WPForms_Constant_Contact extends WPForms_Provider {

	/**
	 * Provider access token.
	 *
	 * @since 1.3.6
	 *
	 * @var string
	 */
	public $access_token;

	/**
	 * Provider API key.
	 *
	 * @since 1.3.6
	 *
	 * @var string
	 */
	public $api_key = 'c58xq3r27udz59h9rrq7qnvf';

	/**
	 * Sign up link.
	 *
	 * @since 1.3.6
	 *
	 * @var string
	 */
	public $sign_up = 'https://constant-contact.evyy.net/c/11535/341874/3411?sharedid=wpforms';

	/**
	 * Initialize.
	 *
	 * @since 1.3.6
	 */
	public function init() {

		$this->version  = '1.3.6';
		$this->name     = 'Constant Contact';
		$this->slug     = 'constant-contact';
		$this->priority = 14;
		$this->icon     = WPFORMS_PLUGIN_URL . 'assets/images/icon-provider-constant-contact.png';

		if ( is_admin() ) {
			// Admin notice requesting connecting.
			$this->connect_request();

			add_action( 'wpforms_admin_notice_dismiss_ajax', [ $this, 'connect_dismiss' ] );
			add_filter( "wpforms_providers_provider_settings_formbuilder_display_content_default_screen_{$this->slug}", [ $this, 'builder_settings_default_content' ] );

			// Provide option to override sign up link.
			$sign_up = get_option( 'wpforms_constant_contact_signup', false );

			if ( $sign_up ) {
				$this->sign_up = esc_html( $sign_up );
			}
		}
	}

	/**
	 * Process and submit entry to provider.
	 *
	 * @since 1.3.6
	 *
	 * @param array $fields    List of fields with their data and settings.
	 * @param array $entry     Submitted entry values.
	 * @param array $form_data Form data and settings.
	 * @param int   $entry_id  Saved entry ID.
	 *
	 * @return void
	 */
	public function process_entry( $fields, $entry, $form_data, $entry_id = 0 ) {

		// Only run if this form has a connections for this provider.
		if ( empty( $form_data['providers'][ $this->slug ] ) ) {
			return;
		}

		/*
		 * Fire for each connection.
		 */

		foreach ( $form_data['providers'][ $this->slug ] as $connection ) :

			// Before proceeding make sure required fields are configured.
			if ( empty( $connection['fields']['email'] ) ) {
				continue;
			}

			// Setup basic data.
			$list_id    = $connection['list_id'];
			$account_id = $connection['account_id'];
			$email_data = explode( '.', $connection['fields']['email'] );
			$email_id   = $email_data[0];
			$email      = $fields[ $email_id ]['value'];

			$this->api_connect( $account_id );

			// Email is required and Access token are required.
			if ( empty( $email ) || empty( $this->access_token ) ) {
				continue;
			}

			// Check for conditionals.
			$pass = $this->process_conditionals( $fields, $entry, $form_data, $connection );
			if ( ! $pass ) {
				wpforms_log(
					'Constant Contact Subscription stopped by conditional logic',
					$fields,
					[
						'type'    => [ 'provider', 'conditional_logic' ],
						'parent'  => $entry_id,
						'form_id' => $form_data['id'],
					]
				);
				continue;
			}

			// Check to see if the lead already exists in Constant Contact.
			$response = wp_remote_get( 'https://api.constantcontact.com/v2/contacts?api_key=' . $this->api_key . '&access_token=' . $this->access_token . '&email=' . $email );
			$contact  = json_decode( wp_remote_retrieve_body( $response ), true );

			// Return early if there was a problem.
			if ( isset( $contact['error_key'] ) ) {
				wpforms_log(
					'Constant Contact API Error',
					$contact->get_error_message(),
					[
						'type'    => [ 'provider', 'error' ],
						'parent'  => $entry_id,
						'form_id' => $form_data['id'],
					]
				);
				continue;
			}

			/*
			 * Setup Merge Vars
			 */

			$merge_vars = [];

			foreach ( $connection['fields'] as $name => $merge_var ) {

				// Don't include Email or Full name fields.
				if ( 'email' === $name ) {
					continue;
				}

				// Check if merge var is mapped.
				if ( empty( $merge_var ) ) {
					continue;
				}

				$merge_var = explode( '.', $merge_var );
				$id        = $merge_var[0];
				$key       = ! empty( $merge_var[1] ) ? $merge_var[1] : 'value';

				// Check if mapped form field has a value.
				if ( empty( $fields[ $id ][ $key ] ) ) {
					continue;
				}

				$value = $fields[ $id ][ $key ];

				// Constant Contact doesn't native URL field so it has to be
				// stored in a custom field.
				if ( $name === 'url' ) {

					$merge_vars['custom_fields'] = [
						[
							'name'  => 'custom_field_1',
							'value' => $value,
						],
					];

					continue;
				}

				// Constant Contact stores name in two fields, so we have to
				// separate it.
				if ( $name === 'full_name' ) {

					$names = explode( ' ', $value );

					if ( ! empty( $names[0] ) ) {
						$merge_vars['first_name'] = $names[0];
					}

					if ( ! empty( $names[1] ) ) {
						$merge_vars['last_name'] = $names[1];
					}

					continue;
				}

				// Constant Contact stores address in multiple fields, so we
				// have to separate it.
				if ( $name === 'address' ) {

					// Only support Address fields.
					if ( $fields[ $id ]['type'] !== 'address' ) {
						continue;
					}

					// Postal code may be in extended US format.
					$postal = [
						'code'    => '',
						'subcode' => '',
					];

					if ( ! empty( $fields[ $id ]['postal'] ) ) {
						$p                 = explode( '-', $fields[ $id ]['postal'] );
						$postal['code']    = ! empty( $p[0] ) ? $p[0] : '';
						$postal['subcode'] = ! empty( $p[1] ) ? $p[1] : '';
					}

					$merge_vars['addresses'] = [
						[
							'address_type'    => 'BUSINESS',
							'city'            => ! empty( $fields[ $id ]['city'] ) ? $fields[ $id ]['city'] : '',
							'country_code'    => ! empty( $fields[ $id ]['country'] ) ? $fields[ $id ]['country'] : '',
							'line1'           => ! empty( $fields[ $id ]['address1'] ) ? $fields[ $id ]['address1'] : '',
							'line2'           => ! empty( $fields[ $id ]['address2'] ) ? $fields[ $id ]['address2'] : '',
							'postal_code'     => $postal['code'],
							'state'           => ! empty( $fields[ $id ]['state'] ) ? $fields[ $id ]['state'] : '',
							'sub_postal_code' => $postal['subcode'],
						],
					];

					continue;
				}

				$merge_vars[ $name ] = $value;
			}

			/*
			 * Process in API
			 */

			// If we have a previous contact, only update the list association.
			if ( ! empty( $contact['results'] ) ) {

				$data = $contact['results'][0];

				// Check if they are already assigned to lists.
				if ( ! empty( $data['lists'] ) ) {

					foreach ( $data['lists'] as $list ) {

						// If they are already assigned to this list, return early.
						if ( isset( $list['id'] ) && (string) $list_id === (string) $list['id'] ) {
							return;
						}
					}

					// Otherwise, add them to the list.
					$data['lists'][ count( $data['lists'] ) ] = [
						'id'     => $list_id,
						'status' => 'ACTIVE',
					];

				} else {

					// Add the contact to the list.
					$data['lists'][0] = [
						'id'     => $list_id,
						'status' => 'ACTIVE',
					];
				}

				// Combine merge vars into data before sending.
				$data = array_merge( $data, $merge_vars );

				// Args to use.
				$args = [
					'body'    => wp_json_encode( $data ),
					'method'  => 'PUT',
					'headers' => [
						'Content-Type' => 'application/json',
					],
				];

				$update = wp_remote_request( 'https://api.constantcontact.com/v2/contacts/' . $data['id'] . '?api_key=' . $this->api_key . '&access_token=' . $this->access_token . '&action_by=ACTION_BY_VISITOR', $args );
				$res    = json_decode( wp_remote_retrieve_body( $update ), true );

			} else {
				// Add a new contact.
				$data = [
					'email_addresses' => [ [ 'email_address' => $email ] ],
					'lists'           => [ [ 'id' => $list_id ] ],
				];

				// Combine merge vars into data before sending.
				$data = array_merge( $data, $merge_vars );

				// Args to use.
				$args = [
					'body'    => wp_json_encode( $data ),
					'headers' => [
						'Content-Type' => 'application/json',
					],
				];

				$add = wp_remote_post( 'https://api.constantcontact.com/v2/contacts?api_key=' . $this->api_key . '&access_token=' . $this->access_token . '&action_by=ACTION_BY_VISITOR', $args );
				$res = json_decode( wp_remote_retrieve_body( $add ), true );
			}

			// Check for errors.
			if ( isset( $res['error_key'] ) ) {
				wpforms_log(
					'Constant Contact API Error',
					$res->get_error_message(),
					[
						'type'    => [ 'provider', 'error' ],
						'parent'  => $entry_id,
						'form_id' => $form_data['id'],
					]
				);
			}

		endforeach;
	}

	/************************************************************************
	 * API methods - these methods interact directly with the provider API. *
	 ************************************************************************/

	/**
	 * Authenticate with the API.
	 *
	 * @since 1.3.6
	 *
	 * @param array  $data    Contact data.
	 * @param string $form_id Form ID.
	 *
	 * @return WP_Error|string Unique ID or error object
	 */
	public function api_auth( $data = [], $form_id = '' ) {

		$this->access_token = isset( $data['authcode'] ) ? $data['authcode'] : '';
		$user               = $this->get_account_information();

		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$id = uniqid();

		wpforms_update_providers_options(
			$this->slug,
			[
				'access_token' => sanitize_text_field( $data['authcode'] ),
				'label'        => sanitize_text_field( $data['label'] ),
				'date'         => time(),
			],
			$id
		);

		return $id;
	}

	/**
	 * Get account information.
	 *
	 * @since 1.7.6
	 *
	 * @return array|WP_Error
	 */
	public function get_account_information() {

		$response = wp_remote_get( 'https://api.constantcontact.com/v2/account/info?api_key=' . $this->api_key . '&access_token=' . $this->access_token );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$user = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! empty( $user[0]['error_key'] ) ) {
			$message = ! empty( $user[0]['error_message'] ) ? $user[0]['error_message'] : '';

			return new WP_Error( $this->slug . '_error', $message );
		}

		return $response;
	}

	/**
	 * Establish connection object to API.
	 *
	 * @since 1.3.6
	 *
	 * @param string $account_id
	 *
	 * @return mixed array or error object.
	 */
	public function api_connect( $account_id ) {

		if ( ! empty( $this->api[ $account_id ] ) ) {
			return $this->api[ $account_id ];
		} else {
			$providers = wpforms_get_providers_options();
			if ( ! empty( $providers[ $this->slug ][ $account_id ] ) ) {
				$this->api[ $account_id ] = true;
				$this->access_token       = $providers[ $this->slug ][ $account_id ]['access_token'];
			} else {
				return $this->error( 'API error' );
			}
		}
	}

	/**
	 * Retrieve provider account lists.
	 *
	 * @since 1.3.6
	 *
	 * @param string $connection_id
	 * @param string $account_id
	 *
	 * @return mixed array or error object
	 */
	public function api_lists( $connection_id = '', $account_id = '' ) {

		$this->api_connect( $account_id );

		$request = wp_remote_get( 'https://api.constantcontact.com/v2/lists?api_key=' . $this->api_key . '&access_token=' . $this->access_token );
		$lists   = json_decode( wp_remote_retrieve_body( $request ), true );

		if ( empty( $lists ) ) {
			wpforms_log(
				'Constant Contact API Error',
				'',
				[
					'type' => [ 'provider', 'error' ],
				]
			);

			return $this->error( esc_html__( 'API list error: Constant API error', 'wpforms-lite' ) );
		}

		return $lists;
	}

	/**
	 * Retrieve provider account list fields.
	 *
	 * @since 1.3.6
	 *
	 * @param string $connection_id
	 * @param string $account_id
	 * @param string $list_id
	 *
	 * @return mixed array or error object
	 */
	public function api_fields( $connection_id = '', $account_id = '', $list_id = '' ) {

		$provider_fields = [
			[
				'name'       => 'Email',
				'field_type' => 'email',
				'req'        => '1',
				'tag'        => 'email',
			],
			[
				'name'       => 'Full Name',
				'field_type' => 'name',
				'tag'        => 'full_name',
			],
			[
				'name'       => 'First Name',
				'field_type' => 'first',
				'tag'        => 'first_name',
			],
			[
				'name'       => 'Last Name',
				'field_type' => 'last',
				'tag'        => 'last_name',
			],
			[
				'name'       => 'Phone',
				'field_type' => 'text',
				'tag'        => 'work_phone',
			],
			[
				'name'       => 'Website',
				'field_type' => 'text',
				'tag'        => 'url',
			],
			[
				'name'       => 'Address',
				'field_type' => 'address',
				'tag'        => 'address',
			],
			[
				'name'       => 'Job Title',
				'field_type' => 'text',
				'tag'        => 'job_title',
			],
			[
				'name'       => 'Company',
				'field_type' => 'text',
				'tag'        => 'company_name',
			],
		];

		return $provider_fields;
	}


	/*************************************************************************
	 * Output methods - these methods generally return HTML for the builder. *
	 *************************************************************************/

	/**
	 * Provider account authorize fields HTML.
	 *
	 * @since 1.3.6
	 *
	 * @return string
	 */
	public function output_auth() {

		$providers = wpforms_get_providers_options();
		$class     = ! empty( $providers[ $this->slug ] ) ? 'hidden' : '';

		ob_start();
		?>

		<div class="wpforms-provider-account-add <?php echo sanitize_html_class( $class ); ?> wpforms-connection-block">

			<h4><?php esc_html_e( 'Add New Account', 'wpforms-lite' ); ?></h4>

			<p>
				<?php esc_html_e( 'Please fill out all of the fields below to register your new Constant Contact account.', 'wpforms-lite' ); ?>
				<br>
				<a href="<?php echo esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-connect-constant-contact-with-wpforms/', 'Marketing Integrations', 'Constant Contact Documentation' ) ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'Click here for documentation on connecting WPForms with Constant Contact.', 'wpforms-lite' ); ?>
				</a>
			</p>

			<p class="wpforms-alert wpforms-alert-warning">
				<?php esc_html_e( 'Because Constant Contact requires external authentication, you will need to register WPForms with Constant Contact before you can proceed.', 'wpforms-lite' ); ?>
			</p>

			<p>
				<strong>
					<a onclick="window.open(this.href,'','resizable=yes,location=no,width=750,height=500,status'); return false" href="https://oauth2.constantcontact.com/oauth2/oauth/siteowner/authorize?response_type=code&client_id=c58xq3r27udz59h9rrq7qnvf&redirect_uri=https://wpforms.com/oauth/constant-contact/" class="btn">
						<?php esc_html_e( 'Click here to register with Constant Contact', 'wpforms-lite' ); ?>
					</a>
				</strong>
			</p>

			<?php
			printf(
				'<input type="text" data-name="authcode" placeholder="%s %s *" class="wpforms-required">',
				esc_attr( $this->name ),
				esc_attr__( 'Authorization Code', 'wpforms-lite' )
			);

			printf(
				'<input type="text" data-name="label" placeholder="%s %s *" class="wpforms-required">',
				esc_attr( $this->name ),
				esc_attr__( 'Account Nickname', 'wpforms-lite' )
			);

			printf(
				'<button data-provider="%s">%s</button>',
				esc_attr( $this->slug ),
				esc_html__( 'Connect', 'wpforms-lite' )
			);

			?>
		</div>

		<?php

		return ob_get_clean();
	}

	/**
	 * Provider account list groups HTML.
	 *
	 * @since 1.3.6
	 *
	 * @param string $connection_id Connection Id.
	 * @param array  $connection    Connection data.
	 *
	 * @return string
	 */
	public function output_groups( $connection_id = '', $connection = [] ) {

		// No groups or segments for this provider.
		return '';
	}

	/**
	 * Default content for the provider settings panel in the form builder.
	 *
	 * @since 1.6.8
	 *
	 * @param string $content Default content.
	 *
	 * @return string
	 */
	public function builder_settings_default_content( $content ) {

		ob_start();
		?>
		<p>
			<a href="<?php echo esc_url( $this->sign_up ); ?>" class="wpforms-btn wpforms-btn-md wpforms-btn-orange" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'Try Constant Contact for Free', 'wpforms-lite' ); ?>
			</a>
		</p>
		<p>
			<?php
			printf(
				'<a href="%s" target="_blank" rel="noopener noreferrer" class="secondary-text">%s</a>',
				esc_url( admin_url( 'admin.php?page=wpforms-page&view=constant-contact' ) ),
				esc_html__( 'Learn more about the power of email marketing.', 'wpforms-lite' )
			);
			?>
		</p>
		<?php

		return $content . ob_get_clean();
	}

	/*************************************************************************
	 * Integrations tab methods - these methods relate to the settings page. *
	 *************************************************************************/

	/**
	 * AJAX to add a provider from the settings integrations tab.
	 *
	 * @since 1.7.6
	 */
	public function integrations_tab_add() {

		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		if ( $_POST['provider'] !== $this->slug ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		$data = ! empty( $_POST['data'] ) ? wp_parse_args( wp_unslash( $_POST['data'] ), [] ) : [];

		if ( empty( $data['authcode'] ) ) {
			wp_send_json_error(
				[
					'error_msg' => esc_html__( 'The "Authorization Code" is required.', 'wpforms-lite' ),
				]
			);
		}

		if ( empty( $data['label'] ) ) {
			wp_send_json_error(
				[
					'error_msg' => esc_html__( 'The "Account Nickname" is required.', 'wpforms-lite' ),
				]
			);
		}

		parent::integrations_tab_add();
	}

	/**
	 * Form fields to add a new provider account.
	 *
	 * @since 1.3.6
	 */
	public function integrations_tab_new_form() {

		?>
		<p>
			<a href="<?php echo esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-connect-constant-contact-with-wpforms/', 'Settings - Integration', 'Constant Contact Documentation' ) ); ?>" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'Click here for documentation on connecting WPForms with Constant Contact.', 'wpforms-lite' ); ?>
			</a>
		</p>

		<p class="wpforms-alert wpforms-alert-warning">
			<?php esc_html_e( 'Because Constant Contact requires external authentication, you will need to register WPForms with Constant Contact before you can proceed.', 'wpforms-lite' ); ?>
		</p>

		<p>
			<strong>
				<a onclick="window.open(this.href,'','resizable=yes,location=no,width=800,height=600,status'); return false" href="https://oauth2.constantcontact.com/oauth2/oauth/siteowner/authorize?response_type=code&client_id=c58xq3r27udz59h9rrq7qnvf&redirect_uri=https://wpforms.com/oauth/constant-contact/" class="btn">
					<?php esc_html_e( 'Click here to register with Constant Contact', 'wpforms-lite' ); ?>
				</a>
			</strong>
		</p>

		<?php
		printf(
			'<input type="text" name="authcode" placeholder="%s %s *" class="wpforms-required">',
			esc_attr( $this->name ),
			esc_attr__( 'Authorization Code', 'wpforms-lite' )
		);

		printf(
			'<input type="text" name="label" placeholder="%s %s *" class="wpforms-required">',
			esc_attr( $this->name ),
			esc_attr__( 'Account Nickname', 'wpforms-lite' )
		);
	}

	/************************
	 * Other functionality. *
	 ************************/

	/**
	 * Add admin notices to connect to Constant Contact.
	 *
	 * @since 1.3.6
	 */
	public function connect_request() {

		// Only consider showing the review request to admin users.
		if ( ! is_super_admin() ) {
			return;
		}

		// Don't display on WPForms admin content pages.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['wpforms-page'] ) ) {
			return;
		}

		// Don't display if user is about to connect via Settings page.
		if ( ! empty( $_GET['wpforms-integration'] ) && $this->slug === $_GET['wpforms-integration'] ) {
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// Only display the notice if the Constant Contact option is set and
		// there are previous Constant Contact connections created.
		// Please do not delete 'wpforms_constant_contact' option check from the code.
		$cc_notice = get_option( 'wpforms_constant_contact', false );
		$providers = wpforms_get_providers_options();

		if ( ! $cc_notice || ! empty( $providers[ $this->slug ] ) ) {
			return;
		}

		// Output the notice message.
		$connect    = admin_url( 'admin.php?page=wpforms-settings&view=integrations&wpforms-integration=constant-contact#!wpforms-tab-providers' );
		$learn_more = admin_url( 'admin.php?page=wpforms-page&view=constant-contact' );

		ob_start();
		?>
		<p>
			<?php
			echo wp_kses(
				__( 'Get the most out of the <strong>WPForms</strong> plugin &mdash; use it with an active Constant Contact account.', 'wpforms-lite' ),
				[
					'strong' => [],
				]
			);
			?>
		</p>
		<p>
			<a href="<?php echo esc_url( $this->sign_up ); ?>" class="button-primary" target="_blank" rel="noopener noreferrer">
				<?php esc_html_e( 'Try Constant Contact for Free', 'wpforms-lite' ); ?>
			</a>
			<a href="<?php echo esc_url( $connect ); ?>" class="button-secondary">
				<?php esc_html_e( 'Connect your existing account', 'wpforms-lite' ); ?>
			</a>
			<?php
			echo wp_kses(
				sprintf( /* translators: %s - WPForms Constant Contact internal URL. */
					__( 'Learn More about the <a href="%s">power of email marketing</a>', 'wpforms-lite' ),
					esc_url( $learn_more )
				),
				[
					'a' => [
						'href' => [],
					],
				]
			);
			?>
		</p>

		<style>
			.wpforms-constant-contact-notice p:first-of-type {
				margin: 16px 0 8px;
			}

			.wpforms-constant-contact-notice p:last-of-type {
				margin: 8px 0 16px;
			}

			.wpforms-constant-contact-notice .button-primary,
			.wpforms-constant-contact-notice .button-secondary {
				margin: 0 10px 0 0;
			}
		</style>
		<?php

		$notice = ob_get_clean();

		\WPForms\Admin\Notice::info(
			$notice,
			[
				'dismiss' => \WPForms\Admin\Notice::DISMISS_GLOBAL,
				'slug'    => 'constant_contact_connect',
				'autop'   => false,
				'class'   => 'wpforms-constant-contact-notice',
			]
		);
	}

	/**
	 * Dismiss the Constant Contact admin notice.
	 *
	 * @since 1.3.6
	 * @since 1.6.7.1 Added parameter $notice_id.
	 *
	 * @param string $notice_id Notice ID (slug).
	 */
	public function connect_dismiss( $notice_id = '' ) {

		if ( $notice_id !== 'global-constant_contact_connect' ) {
			return;
		}

		delete_option( 'wpforms_constant_contact' );

		wp_send_json_success();
	}
}

new WPForms_Constant_Contact();
