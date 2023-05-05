<?php

use WPForms\Providers\Provider\Settings\FormBuilder;
use WPForms\Providers\Provider\Status;

/**
 * Provider class.
 *
 * @since 1.0.0
 */
abstract class WPForms_Provider {

	/**
	 * Provider addon version.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	protected $version;

	/**
	 * Provider name.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $name;

	/**
	 * Provider name in slug format.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $slug;

	/**
	 * Load priority.
	 *
	 * @since 1.0.0
	 *
	 * @var int
	 */
	public $priority = 10;

	/**
	 * Store the API connections.
	 *
	 * @since 1.0.0
	 *
	 * @var mixed
	 */
	public $api = false;

	/**
	 * Service icon.
	 *
	 * @since 1.0.0
	 *
	 * @var string
	 */
	public $icon;

	/**
	 * Service icon.
	 *
	 * @since 1.2.3
	 *
	 * @var string
	 */
	public $type;

	/**
	 * Form data and settings.
	 *
	 * @since 1.2.3
	 *
	 * @var array
	 */
	public $form_data;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		$this->type = esc_html__( 'Connection', 'wpforms-lite' );

		$this->init();
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.8
	 */
	private function hooks() {

		// Add to list of available providers.
		add_filter( 'wpforms_providers_available', [ $this, 'register_provider' ], $this->priority, 1 );

		// Process builder AJAX requests.
		add_action( "wp_ajax_wpforms_provider_ajax_{$this->slug}", [ $this, 'process_ajax' ] );

		// Process entry.
		add_action( 'wpforms_process_complete', [ $this, 'process_entry' ], 5, 4 );

		// Fetch and store the current form data when in the builder.
		add_action( 'wpforms_builder_init', [ $this, 'builder_form_data' ] );

		// Output builder sidebar.
		add_action( 'wpforms_providers_panel_sidebar', [ $this, 'builder_sidebar' ], $this->priority );

		// Output builder content.
		add_action( 'wpforms_providers_panel_content', [ $this, 'builder_output' ], $this->priority );

		// Remove provider from Settings Integrations tab.
		add_action( "wp_ajax_wpforms_settings_provider_disconnect_{$this->slug}", [ $this, 'integrations_tab_disconnect' ] );

		// Add new provider from Settings Integrations tab.
		add_action( "wp_ajax_wpforms_settings_provider_add_{$this->slug}", [ $this, 'integrations_tab_add' ] );

		// Add providers sections to the Settings Integrations tab.
		add_action( 'wpforms_settings_providers', [ $this, 'integrations_tab_options' ], $this->priority, 2 );
	}

	/**
	 * Add to list of registered providers.
	 *
	 * @since 1.0.0
	 *
	 * @param array $providers Array of all active providers.
	 *
	 * @return array
	 */
	public function register_provider( $providers = [] ) {

		$providers[ $this->slug ] = $this->name;

		return $providers;
	}

	/**
	 * Process the Builder AJAX requests.
	 *
	 * @since 1.0.0
	 */
	public function process_ajax() {

		// Run a security check.
		check_ajax_referer( 'wpforms-builder', 'nonce' );

		// Check for permissions.
		if ( ! wpforms_current_user_can( 'edit_forms' ) ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'You do not have permission', 'wpforms-lite' ),
				]
			);
		}

		$name          = ! empty( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$task          = ! empty( $_POST['task'] ) ? sanitize_text_field( wp_unslash( $_POST['task'] ) ) : '';
		$id            = ! empty( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$connection_id = ! empty( $_POST['connection_id'] ) ? sanitize_text_field( wp_unslash( $_POST['connection_id'] ) ) : '';
		$account_id    = ! empty( $_POST['account_id'] ) ? sanitize_text_field( wp_unslash( $_POST['account_id'] ) ) : '';
		$list_id       = ! empty( $_POST['list_id'] ) ? sanitize_text_field( wp_unslash( $_POST['list_id'] ) ) : '';
		$data          = ! empty( $_POST['data'] ) ? array_map( 'sanitize_text_field', wp_parse_args( wp_unslash( $_POST['data'] ) ) ) : []; //phpcs:ignore

		/*
		 * Create new connection.
		 */

		if ( 'new_connection' === $task ) {

			$connection = $this->output_connection(
				'',
				[
					'connection_name' => $name,
				],
				$id
			);
			wp_send_json_success(
				[
					'html' => $connection,
				]
			);
		}

		/*
		 * Create new Provider account.
		 */

		if ( 'new_account' === $task ) {

			$auth = $this->api_auth( $data, $id );

			if ( is_wp_error( $auth ) ) {

				wp_send_json_error(
					[
						'error' => $auth->get_error_message(),
					]
				);

			} else {

				$accounts = $this->output_accounts(
					$connection_id,
					[
						'account_id' => $auth,
					]
				);
				wp_send_json_success(
					[
						'html' => $accounts,
					]
				);
			}
		}

		/*
		 * Select/Toggle Provider accounts.
		 */

		if ( 'select_account' === $task ) {

			$lists = $this->output_lists(
				$connection_id,
				[
					'account_id' => $account_id,
				]
			);

			if ( is_wp_error( $lists ) ) {

				wp_send_json_error(
					[
						'error' => $lists->get_error_message(),
					]
				);

			} else {

				wp_send_json_success(
					[
						'html' => $lists,
					]
				);
			}
		}

		/*
		 * Select/Toggle Provider account lists.
		 */

		if ( 'select_list' === $task ) {

			$fields = $this->output_fields(
				$connection_id,
				[
					'account_id' => $account_id,
					'list_id'    => $list_id,
				],
				$id
			);

			if ( is_wp_error( $fields ) ) {

				wp_send_json_error(
					[
						'error' => $fields->get_error_message(),
					]
				);

			} else {

				$groups = $this->output_groups(
					$connection_id,
					[
						'account_id' => $account_id,
						'list_id'    => $list_id,
					]
				);

				$conditionals = $this->output_conditionals(
					$connection_id,
					[
						'account_id' => $account_id,
						'list_id'    => $list_id,
					],
					[
						'id' => absint( $_POST['form_id'] ), //phpcs:ignore
					]
				);

				$options = $this->output_options(
					$connection_id,
					[
						'account_id' => $account_id,
						'list_id'    => $list_id,
					]
				);

				wp_send_json_success(
					[
						'html' => $groups . $fields . $conditionals . $options,
					]
				);
			}
		}

		die();
	}

	/**
	 * Process and submit entry to provider.
	 *
	 * @since 1.0.0
	 *
	 * @param array $fields    List of fields in a form.
	 * @param array $entry     Submitted entry values.
	 * @param array $form_data Form data and settings.
	 * @param int   $entry_id  Saved entry ID.
	 */
	public function process_entry( $fields, $entry, $form_data, $entry_id ) {
	}

	/**
	 * Process conditional fields.
	 *
	 * @since 1.0.0
	 *
	 * @param array $fields     List of fields with their data and settings.
	 * @param array $entry      Submitted entry values.
	 * @param array $form_data  Form data and settings.
	 * @param array $connection List of connection settings.
	 *
	 * @return bool
	 */
	public function process_conditionals( $fields, $entry, $form_data, $connection ) {

		if (
			empty( $connection['conditional_logic'] ) ||
			empty( $connection['conditionals'] ) ||
			! function_exists( 'wpforms_conditional_logic' )
		) {
			return true;
		}

		$process = wpforms_conditional_logic()->process( $fields, $form_data, $connection['conditionals'] );

		if ( ! empty( $connection['conditional_type'] ) && $connection['conditional_type'] === 'stop' ) {
			$process = ! $process;
		}

		return $process;
	}

	/**
	 * Retrieve all available forms in a field.
	 *
	 * Not all fields should be available for merge tags so we compare against a
	 * white-list. Also some fields, such as Name, should have additional
	 * variations.
	 *
	 * @since 1.0.0
	 *
	 * @param object|bool $form
	 * @param array $whitelist
	 *
	 * @return bool|array
	 */
	public function get_form_fields( $form = false, $whitelist = [] ) {

		// Accept form (post) object or form ID.
		if ( is_object( $form ) ) {
			$form = wpforms_decode( $form->post_content );
		} elseif ( is_numeric( $form ) ) {
			$form = wpforms()->form->get(
				$form,
				[
					'content_only' => true,
				]
			);
		}

		if ( ! is_array( $form ) || empty( $form['fields'] ) ) {
			return false;
		}

		// White list of field types to allow.
		$allowed_form_fields = [
			'text',
			'textarea',
			'select',
			'radio',
			'checkbox',
			'email',
			'address',
			'url',
			'name',
			'hidden',
			'date-time',
			'phone',
			'number',
		];
		$allowed_form_fields = apply_filters( 'wpforms_providers_fields', $allowed_form_fields );

		$whitelist = ! empty( $whitelist ) ? $whitelist : $allowed_form_fields;

		$form_fields = $form['fields'];

		foreach ( $form_fields as $id => $form_field ) {
			if ( ! in_array( $form_field['type'], $whitelist, true ) ) {
				unset( $form_fields[ $id ] );
			}
		}

		return $form_fields;
	}

	/**
	 * Get form fields ready for select list options.
	 *
	 * In this function we also do the logic to limit certain fields to certain
	 * provider field types.
	 *
	 * @since 1.0.0
	 *
	 * @param array $form_fields
	 * @param string $form_field_type
	 *
	 * @return array
	 */
	public function get_form_field_select( $form_fields = [], $form_field_type = '' ) {

		if ( empty( $form_fields ) || empty( $form_field_type ) ) {
			return [];
		}

		$formatted = [];

		// Include only specific field types.
		foreach ( $form_fields as $id => $form_field ) {

			// Email.
			if (
				'email' === $form_field_type &&
				! in_array( $form_field['type'], [ 'text', 'email' ], true )
			) {
				unset( $form_fields[ $id ] );
			}

			// Address.
			if (
				'address' === $form_field_type &&
				! in_array( $form_field['type'], [ 'address' ], true )
			) {
				unset( $form_fields[ $id ] );
			}
		}

		// Format.
		foreach ( $form_fields as $id => $form_field ) {

			// Complex Name field.
			if ( 'name' === $form_field['type'] ) {

				// Full Name.
				$formatted[] = [
					'id'            => $form_field['id'],
					'key'           => 'value',
					'type'          => $form_field['type'],
					'subtype'       => '',
					'provider_type' => $form_field_type,
					'label'         => sprintf(
						/* translators: %s - Name field label. */
						esc_html__( '%s (Full)', 'wpforms-lite' ),
						$form_field['label']
					),
				];

				// First Name.
				if ( strpos( $form_field['format'], 'first' ) !== false ) {
					$formatted[] = [
						'id'            => $form_field['id'],
						'key'           => 'first',
						'type'          => $form_field['type'],
						'subtype'       => 'first',
						'provider_type' => $form_field_type,
						'label'         => sprintf(
							/* translators: %s - Name field label. */
							esc_html__( '%s (First)', 'wpforms-lite' ),
							$form_field['label']
						),
					];
				}

				// Middle Name.
				if ( strpos( $form_field['format'], 'middle' ) !== false ) {
					$formatted[] = [
						'id'            => $form_field['id'],
						'key'           => 'middle',
						'type'          => $form_field['type'],
						'subtype'       => 'middle',
						'provider_type' => $form_field_type,
						'label'         => sprintf(
							/* translators: %s - Name field label. */
							esc_html__( '%s (Middle)', 'wpforms-lite' ),
							$form_field['label']
						),
					];
				}

				// Last Name.
				if ( strpos( $form_field['format'], 'last' ) !== false ) {
					$formatted[] = [
						'id'            => $form_field['id'],
						'key'           => 'last',
						'type'          => $form_field['type'],
						'subtype'       => 'last',
						'provider_type' => $form_field_type,
						'label'         => sprintf(
							/* translators: %s - Name field label. */
							esc_html__( '%s (Last)', 'wpforms-lite' ),
							$form_field['label']
						),
					];
				}
			} else {
				// All other fields.
				$formatted[] = [
					'id'            => $form_field['id'],
					'key'           => 'value',
					'type'          => $form_field['type'],
					'subtype'       => '',
					'provider_type' => $form_field_type,
					'label'         => $form_field['label'],
				];
			}
		}

		return $formatted;
	}

	/************************************************************************
	 * API methods - these methods interact directly with the provider API. *
	 ************************************************************************/

	/**
	 * Authenticate with the provider API.
	 *
	 * @since 1.0.0
	 *
	 * @param array $data
	 * @param string $form_id
	 *
	 * @return mixed id or error object
	 */
	public function api_auth( $data = [], $form_id = '' ) {
	}

	/**
	 * Establish connection object to provider API.
	 *
	 * @since 1.0.0
	 *
	 * @param string $account_id
	 *
	 * @return mixed array or error object
	 */
	public function api_connect( $account_id ) {
	}

	/**
	 * Retrieve provider account lists.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param string $account_id
	 *
	 * @return mixed array or error object
	 */
	public function api_lists( $connection_id = '', $account_id = '' ) {
	}

	/**
	 * Retrieve provider account list groups.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param string $account_id
	 * @param string $list_id
	 *
	 * @return mixed array or error object
	 */
	public function api_groups( $connection_id = '', $account_id = '', $list_id = '' ) {
	}

	/**
	 * Retrieve provider account list fields.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param string $account_id
	 * @param string $list_id
	 *
	 * @return mixed array or error object
	 */
	public function api_fields( $connection_id = '', $account_id = '', $list_id = '' ) {
	}

	/*************************************************************************
	 * Output methods - these methods generally return HTML for the builder. *
	 *************************************************************************/

	/**
	 * Connection HTML.
	 *
	 * This method compiles all the HTML necessary for a connection to a provider.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 * @param mixed $form Form id or form data.
	 *
	 * @return string
	 */
	public function output_connection( $connection_id = '', $connection = [], $form = '' ) {

		if ( empty( $connection_id ) ) {
			$connection_id = 'connection_' . uniqid();
		}

		if ( empty( $connection ) || empty( $form ) ) {
			return '';
		}

		$output = sprintf( '<div class="wpforms-provider-connection" data-provider="%s" data-connection_id="%s">', $this->slug, $connection_id );

		$output .= $this->output_connection_header( $connection_id, $connection );

		$output .= $this->output_auth();

		$output .= $this->output_accounts( $connection_id, $connection );

		$lists   = $this->output_lists( $connection_id, $connection );
		$output .= ! is_wp_error( $lists ) ? $lists : '';

		$output .= $this->output_groups( $connection_id, $connection );

		$fields  = $this->output_fields( $connection_id, $connection, $form );
		$output .= ! is_wp_error( $fields ) ? $fields : '';

		$output .= $this->output_conditionals( $connection_id, $connection, $form );

		$output .= $this->output_options( $connection_id, $connection );

		$output .= '</div>';

		return $output;
	}

	/**
	 * Connection header HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 *
	 * @return string
	 */
	public function output_connection_header( $connection_id = '', $connection = [] ) {

		if ( empty( $connection_id ) || empty( $connection ) ) {
			return '';
		}

		$output = '<div class="wpforms-provider-connection-header">';

		$output .= sprintf( '<span>%s</span>', sanitize_text_field( $connection['connection_name'] ) );

		$output .= '<button class="wpforms-provider-connection-delete"><i class="fa fa-trash-o"></i></button>';

		$output .= sprintf( '<input type="hidden" name="providers[%s][%s][connection_name]" value="%s">', $this->slug, $connection_id, esc_attr( $connection['connection_name'] ) );

		$output .= '</div>';

		return $output;
	}

	/**
	 * Provider account authorize fields HTML.
	 *
	 * @since 1.0.0
	 *
	 * @return mixed
	 */
	public function output_auth() {
	}

	/**
	 * Provider account select HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id Unique connection ID.
	 * @param array  $connection Array of connection data.
	 *
	 * @return string
	 */
	public function output_accounts( $connection_id = '', $connection = [] ) {

		if ( empty( $connection_id ) || empty( $connection ) ) {
			return '';
		}

		$providers = wpforms_get_providers_options();

		if ( empty( $providers[ $this->slug ] ) ) {
			return '';
		}

		$output = '<div class="wpforms-provider-accounts wpforms-connection-block">';

		$output .= sprintf( '<h4>%s</h4>', esc_html__( 'Select Account', 'wpforms-lite' ) );

		$output .= sprintf( '<select name="providers[%s][%s][account_id]">', $this->slug, $connection_id );
		foreach ( $providers[ $this->slug ] as $key => $provider_details ) {
			$selected = ! empty( $connection['account_id'] ) ? $connection['account_id'] : '';
			$output  .= sprintf(
				'<option value="%s" %s>%s</option>',
				$key,
				selected( $selected, $key, false ),
				esc_html( $provider_details['label'] )
			);
		}
		$output .= sprintf( '<option value="">%s</a>', esc_html__( 'Add New Account', 'wpforms-lite' ) );
		$output .= '</select>';

		$output .= '</div>';

		return $output;
	}

	/**
	 * Provider account lists HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 *
	 * @return WP_Error|string
	 */
	public function output_lists( $connection_id = '', $connection = [] ) {

		if ( empty( $connection_id ) || empty( $connection['account_id'] ) ) {
			return '';
		}

		$lists    = $this->api_lists( $connection_id, $connection['account_id'] );
		$selected = ! empty( $connection['list_id'] ) ? $connection['list_id'] : '';

		if ( is_wp_error( $lists ) ) {
			return $lists;
		}

		$output = '<div class="wpforms-provider-lists wpforms-connection-block">';

		$output .= sprintf( '<h4>%s</h4>', esc_html__( 'Select List', 'wpforms-lite' ) );

		$output .= sprintf( '<select name="providers[%s][%s][list_id]">', $this->slug, $connection_id );

		if ( ! empty( $lists ) ) {
			foreach ( $lists as $list ) {
				$output .= sprintf(
					'<option value="%s" %s>%s</option>',
					esc_attr( $list['id'] ),
					selected( $selected, $list['id'], false ),
					esc_attr( $list['name'] )
				);
			}
		}

		$output .= '</select>';

		$output .= '</div>';

		return $output;
	}

	/**
	 * Provider account list groups HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 *
	 * @return string
	 */
	public function output_groups( $connection_id = '', $connection = [] ) {

		if ( empty( $connection_id ) || empty( $connection['account_id'] ) || empty( $connection['list_id'] ) ) {
			return '';
		}

		$groupsets = $this->api_groups( $connection_id, $connection['account_id'], $connection['list_id'] );

		if ( is_wp_error( $groupsets ) ) {
			return '';
		}

		$output = '<div class="wpforms-provider-groups wpforms-connection-block">';

		$output .= sprintf( '<h4>%s</h4>', esc_html__( 'Select Groups', 'wpforms-lite' ) );

		$output .= sprintf( '<p>%s</p>', esc_html__( 'We also noticed that you have some segments in your list. You can select specific list segments below if needed. This is optional.', 'wpforms-lite' ) );

		$output .= '<div class="wpforms-provider-groups-list">';

		foreach ( $groupsets as $groupset ) {

			$output .= sprintf( '<p>%s</p>', esc_html( $groupset['name'] ) );

			foreach ( $groupset['groups'] as $group ) {

				$selected = ! empty( $connection['groups'] ) && ! empty( $connection['groups'][ $groupset['id'] ] ) ? in_array( $group['name'], $connection['groups'][ $groupset['id'] ], true ) : false;

				$output .= sprintf(
					'<span><input id="group_%s" type="checkbox" value="%s" name="providers[%s][%s][groups][%s][%s]" %s><label for="group_%s">%s</label></span>',
					esc_attr( $group['id'] ),
					esc_attr( $group['name'] ),
					$this->slug,
					$connection_id,
					$groupset['id'],
					$group['id'],
					checked( $selected, true, false ),
					esc_attr( $group['id'] ),
					esc_attr( $group['name'] )
				);
			}
		}

		$output .= '</div>';

		$output .= '</div>';

		return $output;
	}

	/**
	 * Provider account list fields HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 * @param mixed $form
	 *
	 * @return WP_Error|string
	 */
	public function output_fields( $connection_id = '', $connection = [], $form = '' ) {

		if ( empty( $connection_id ) || empty( $connection['account_id'] ) || empty( $connection['list_id'] ) || empty( $form ) ) {
			return '';
		}

		$provider_fields = $this->api_fields( $connection_id, $connection['account_id'], $connection['list_id'] );
		$form_fields     = $this->get_form_fields( $form );

		if ( is_wp_error( $provider_fields ) ) {
			return $provider_fields;
		}

		$output = '<div class="wpforms-provider-fields wpforms-connection-block">';

		$output .= sprintf( '<h4>%s</h4>', esc_html__( 'List Fields', 'wpforms-lite' ) );

		// Table with all the fields.
		$output .= '<table>';

		$output .= sprintf( '<thead><tr><th>%s</th><th>%s</th></thead>', esc_html__( 'List Fields', 'wpforms-lite' ), esc_html__( 'Available Form Fields', 'wpforms-lite' ) );

		$output .= '<tbody>';

		foreach ( $provider_fields as $provider_field ) :

			$output .= '<tr>';

			$output .= '<td>';

			$output .= esc_html( $provider_field['name'] );
			if (
				! empty( $provider_field['req'] ) &&
				(int) $provider_field['req'] === 1
			) {
				$output .= '<span class="required">*</span>';
			}

			$output .= '<td>';

			$output .= sprintf( '<select name="providers[%s][%s][fields][%s]">', $this->slug, $connection_id, esc_attr( $provider_field['tag'] ) );

			$output .= '<option value=""></option>';

			$options = $this->get_form_field_select( $form_fields, $provider_field['field_type'] );

			foreach ( $options as $option ) {
				$value    = sprintf( '%d.%s.%s', $option['id'], $option['key'], $option['provider_type'] );
				$selected = ! empty( $connection['fields'][ $provider_field['tag'] ] ) ? selected( $connection['fields'][ $provider_field['tag'] ], $value, false ) : '';
				$output  .= sprintf( '<option value="%s" %s>%s</option>', esc_attr( $value ), $selected, esc_html( $option['label'] ) );
			}

			$output .= '</select>';

			$output .= '</td>';

			$output .= '</tr>';

		endforeach;

		$output .= '</tbody>';

		$output .= '</table>';

		$output .= '</div>';

		return $output;
	}

	/**
	 * Provider connection conditional options HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string       $connection_id Unique connection ID.
	 * @param array        $connection    Configured connection properties.
	 * @param string|array $form          Form properties.
	 *
	 * @return string
	 */
	public function output_conditionals( $connection_id = '', $connection = [], $form = '' ) {

		if ( empty( $connection['account_id'] ) || ! function_exists( 'wpforms_conditional_logic' ) ) {
			return '';
		}

		return wpforms_conditional_logic()->builder_block(
			[
				'form'       => $this->form_data,
				'type'       => 'panel',
				'panel'      => $this->slug,
				'parent'     => 'providers',
				'subsection' => $connection_id,
				'reference'  => esc_html__( 'Marketing provider connection', 'wpforms-lite' ),
			],
			false
		);
	}


	/**
	 * Provider account list options HTML.
	 *
	 * @since 1.0.0
	 *
	 * @param string $connection_id
	 * @param array $connection
	 *
	 * @return string
	 */
	public function output_options( $connection_id = '', $connection = [] ) {
	}

	/********************************************************
	 * Builder methods - these methods _build_ the Builder. *
	 ********************************************************/

	/**
	 * Fetch and store the current form data when in the builder.
	 *
	 * @since 1.2.3
	 */
	public function builder_form_data() {

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['form_id'] ) || ! empty( $this->form_data ) ) {
			return;
		}

		$revisions = wpforms()->get( 'revisions' );
		$revision  = $revisions ? $revisions->get_revision() : null;

		if ( $revision ) {
			// Setup form data based on the revision_id.
			$this->form_data = wpforms_decode( $revision->post_content );

			return;
		}

		// Setup form data based on the ID.
		$form = wpforms()->get( 'form' );

		if ( ! $form ) {
			return;
		}

		$this->form_data = $form->get(
			absint( $_GET['form_id'] ),
			[ 'content_only' => true ]
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	/**
	 * Display content inside the panel content area.
	 *
	 * @since 1.0.0
	 */
	public function builder_content() {

		$form_data = $this->form_data;
		$providers = wpforms_get_providers_options();

		if ( ! empty( $form_data['providers'][ $this->slug ] ) && ! empty( $providers[ $this->slug ] ) ) {

			foreach ( $form_data['providers'][ $this->slug ] as $connection_id => $connection ) {

				foreach ( $providers[ $this->slug ] as $account_id => $connections ) {

					if (
						! empty( $connection['account_id'] ) &&
						$connection['account_id'] === $account_id
					) {
						echo $this->output_connection( $connection_id, $connection, $form_data );
					}
				}
			}
		}
	}

	/**
	 * Get provider configured status.
	 *
	 * @since 1.6.8
	 */
	private function get_configured() {

		return ! empty( $this->form_data['id'] ) && Status::init( $this->slug )->is_ready( $this->form_data['id'] )
			? 'configured'
			: '';
	}

	/**
	 * Display content inside the panel sidebar area.
	 *
	 * @since 1.0.0
	 */
	public function builder_sidebar() {

		$configured = $this->get_configured();

		echo '<a href="#" class="wpforms-panel-sidebar-section icon ' . esc_attr( $configured ) . ' wpforms-panel-sidebar-section-' . esc_attr( $this->slug ) . '" data-section="' . esc_attr( $this->slug ) . '">';

		echo '<img src="' . esc_url( $this->icon ) . '">';

		echo esc_html( $this->name );

		echo '<i class="fa fa-angle-right wpforms-toggle-arrow"></i>';

		if ( ! empty( $configured ) ) {
			echo '<i class="fa fa-check-circle-o"></i>';
		}

		echo '</a>';
	}

	/**
	 * Wrap the builder content with the required markup.
	 *
	 * @since 1.0.0
	 */
	public function builder_output() {

		$form_id = ! empty( $this->form_data['id'] ) ? $this->form_data['id'] : '';

		?>
		<div class="wpforms-panel-content-section wpforms-panel-content-section-<?php echo esc_attr( $this->slug ); ?>"
			id="<?php echo esc_attr( $this->slug ); ?>-provider">

			<?php $this->builder_output_before(); ?>

			<div class="wpforms-panel-content-section-title">

				<?php echo esc_html( $this->name ); ?>

				<button class="wpforms-provider-connections-add" data-form_id="<?php echo absint( $form_id ); ?>"
					data-provider="<?php echo esc_attr( $this->slug ); ?>"
					data-type="<?php echo esc_attr( strtolower( $this->type ) ); ?>">
					<?php
					printf( /* translators: %s - Provider type. */
						esc_html__( 'Add New %s', 'wpforms-lite' ),
						esc_html( $this->type )
					);
					?>
				</button>

			</div>
			<?php

			FormBuilder::display_content_default_screen(
				Status::init( $this->slug )->is_ready( $form_id ),
				$this->slug,
				$this->name,
				$this->icon
			);

			?>
			<div class="wpforms-provider-connections-wrap wpforms-clear">

				<div class="wpforms-provider-connections">

					<?php $this->builder_content(); ?>

				</div>

			</div>

			<?php $this->builder_output_after(); ?>

		</div>
		<?php
	}

	/**
	 * Optionally output content before the main builder output.
	 *
	 * @since 1.3.6
	 */
	public function builder_output_before() {
	}

	/**
	 * Optionally output content after the main builder output.
	 *
	 * @since 1.3.6
	 */
	public function builder_output_after() {
	}

	/*************************************************************************
	 * Integrations tab methods - these methods relate to the settings page. *
	 *************************************************************************/

	/**
	 * Form fields to add a new provider account.
	 *
	 * @since 1.0.0
	 */
	public function integrations_tab_new_form() {
	}

	/**
	 * AJAX to disconnect a provider from the settings integrations tab.
	 *
	 * @since 1.0.0
	 */
	public function integrations_tab_disconnect() {

		// Run a security check.
		check_ajax_referer( 'wpforms-admin', 'nonce' );

		// Check for permissions.
		if ( ! wpforms_current_user_can() ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'You do not have permission', 'wpforms-lite' ),
				]
			);
		}

		if ( empty( $_POST['provider'] ) || empty( $_POST['key'] ) ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'Missing data', 'wpforms-lite' ),
				]
			);
		}

		$providers = wpforms_get_providers_options();

		if ( ! empty( $providers[ $_POST['provider'] ][ $_POST['key'] ] ) ) {

			unset( $providers[ $_POST['provider'] ][ $_POST['key'] ] );
			update_option( 'wpforms_providers', $providers );
			wp_send_json_success();

		} else {
			wp_send_json_error(
				[
					'error' => esc_html__( 'Connection missing', 'wpforms-lite' ),
				]
			);
		}
	}

	/**
	 * AJAX to add a provider from the settings integrations tab.
	 *
	 * @since 1.0.0
	 */
	public function integrations_tab_add() {

		if ( $_POST['provider'] !== $this->slug ) { //phpcs:ignore
			return;
		}

		// Run a security check.
		check_ajax_referer( 'wpforms-admin', 'nonce' );

		// Check for permissions.
		if ( ! wpforms_current_user_can() ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'You do not have permission', 'wpforms-lite' ),
				]
			);
		}

		if ( empty( $_POST['data'] ) ) {
			wp_send_json_error(
				[
					'error' => esc_html__( 'Missing data', 'wpforms-lite' ),
				]
			);
		}

		$data = wp_parse_args( $_POST['data'], [] );
		$auth = $this->api_auth( $data, '' );

		if ( is_wp_error( $auth ) ) {

			wp_send_json_error(
				[
					'error'     => esc_html__( 'Could not connect to the provider.', 'wpforms-lite' ),
					'error_msg' => $auth->get_error_message(),
				]
			);

		} else {

			$account  = '<li class="wpforms-clear">';
			$account .= '<span class="label">' . sanitize_text_field( $data['label'] ) . '</span>';
			/* translators: %s - Connection date. */
			$account .= '<span class="date">' . sprintf( esc_html__( 'Connected on: %s', 'wpforms-lite' ), date_i18n( get_option( 'date_format', time() ) ) ) . '</span>';
			$account .= '<span class="remove"><a href="#" data-provider="' . $this->slug . '" data-key="' . esc_attr( $auth ) . '">' . esc_html__( 'Disconnect', 'wpforms-lite' ) . '</a></span>';
			$account .= '</li>';

			wp_send_json_success(
				[
					'html' => $account,
				]
			);
		}
	}

	/**
	 * Add provider to the Settings Integrations tab.
	 *
	 * @since 1.0.0
	 *
	 * @param array $active   Array of active connections.
	 * @param array $settings Array of all connections settings.
	 */
	public function integrations_tab_options( $active, $settings ) {

		$connected = ! empty( $active[ $this->slug ] );
		$accounts  = ! empty( $settings[ $this->slug ] ) ? $settings[ $this->slug ] : [];
		$class     = $connected && $accounts ? 'connected' : '';
		$arrow     = 'right';
		/* translators: %s - provider name. */
		$title_connect_to = sprintf( esc_html__( 'Connect to %s', 'wpforms-lite' ), esc_html( $this->name ) );

		// This lets us highlight a specific service by a special link.
		if ( ! empty( $_GET['wpforms-integration'] ) ) { //phpcs:ignore
			if ( $this->slug === $_GET['wpforms-integration'] ) { //phpcs:ignore
				$class .= ' focus-in';
				$arrow  = 'down';
			} else {
				$class .= ' focus-out';
			}
		}
		?>

		<div id="wpforms-integration-<?php echo esc_attr( $this->slug ); ?>" class="wpforms-settings-provider wpforms-clear <?php echo esc_attr( $this->slug ); ?> <?php echo esc_attr( $class ); ?>">

			<div class="wpforms-settings-provider-header wpforms-clear" data-provider="<?php echo esc_attr( $this->slug ); ?>">

				<div class="wpforms-settings-provider-logo">
					<i title="<?php esc_attr_e( 'Show Accounts', 'wpforms-lite' ); ?>" class="fa fa-chevron-<?php echo esc_attr( $arrow ); ?>"></i>
					<img src="<?php echo esc_url( $this->icon ); ?>">
				</div>

				<div class="wpforms-settings-provider-info">
					<h3><?php echo esc_html( $this->name ); ?></h3>
					<p>
						<?php
						/* translators: %s - provider name. */
						printf( esc_html__( 'Integrate %s with WPForms', 'wpforms-lite' ), esc_html( $this->name ) );
						?>
					</p>
					<span class="connected-indicator green"><i class="fa fa-check-circle-o"></i>&nbsp;<?php esc_html_e( 'Connected', 'wpforms-lite' ); ?></span>
				</div>

			</div>

			<div class="wpforms-settings-provider-accounts" id="provider-<?php echo esc_attr( $this->slug ); ?>">

				<div class="wpforms-settings-provider-accounts-list">
					<ul>
						<?php
						if ( ! empty( $accounts ) ) {
							foreach ( $accounts as $key => $account ) {
								echo '<li class="wpforms-clear">';
								echo '<span class="label">' . esc_html( $account['label'] ) . '</span>';
								/* translators: %s - Connection date. */
								echo '<span class="date">' . sprintf( esc_html__( 'Connected on: %s', 'wpforms-lite' ), date_i18n( get_option( 'date_format' ), intval( $account['date'] ) ) ) . '</span>';
								echo '<span class="remove"><a href="#" data-provider="' . esc_attr( $this->slug ) . '" data-key="' . esc_attr( $key ) . '">' . esc_html__( 'Disconnect', 'wpforms-lite' ) . '</a></span>';
								echo '</li>';
							}
						}
						?>
					</ul>
				</div>

				<p class="wpforms-settings-provider-accounts-toggle">
					<a class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey" href="#" data-provider="<?php echo esc_attr( $this->slug ); ?>">
						<i class="fa fa-plus"></i> <?php esc_html_e( 'Add New Account', 'wpforms-lite' ); ?>
					</a>
				</p>

				<div class="wpforms-settings-provider-accounts-connect">

					<form>
						<p><?php esc_html_e( 'Please fill out all of the fields below to add your new provider account.', 'wpforms-lite' ); ?></span></p>

						<p class="wpforms-settings-provider-accounts-connect-fields">
							<?php $this->integrations_tab_new_form(); ?>
						</p>

						<button type="submit" class="wpforms-btn wpforms-btn-md wpforms-btn-orange wpforms-settings-provider-connect"
							data-provider="<?php echo esc_attr( $this->slug ); ?>" title="<?php echo esc_attr( $title_connect_to ); ?>">
							<?php echo esc_html( $title_connect_to ); ?>
						</button>
					</form>
				</div>

			</div>

		</div>
		<?php
	}

	/**
	 * Error wrapper for WP_Error.
	 *
	 * @since 1.0.0
	 *
	 * @param string $message
	 * @param string $parent
	 *
	 * @return WP_Error
	 */
	public function error( $message = '', $parent = '0' ) {
		return new WP_Error( $this->slug . '-error', $message );
	}
}
