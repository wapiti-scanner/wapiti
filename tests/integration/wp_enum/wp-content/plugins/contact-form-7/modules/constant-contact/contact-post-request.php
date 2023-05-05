<?php

class WPCF7_ConstantContact_ContactPostRequest {

	private $email_address;
	private $first_name;
	private $last_name;
	private $job_title;
	private $company_name;
	private $create_source;
	private $birthday_month;
	private $birthday_day;
	private $anniversary;
	private $custom_fields = array();
	private $phone_numbers = array();
	private $street_addresses = array();
	private $list_memberships = array();

	public function __construct() {
	}

	public function build( WPCF7_Submission $submission ) {
		$this->set_create_source( 'Contact' );

		$this->set_first_name(
			$submission->get_posted_string( 'your-first-name' )
		);

		$this->set_last_name(
			$submission->get_posted_string( 'your-last-name' )
		);

		if ( ! ( $this->first_name || $this->last_name )
		and $your_name = $submission->get_posted_string( 'your-name' ) ) {
			$your_name = preg_split( '/[\s]+/', $your_name, 2 );
			$this->set_first_name( array_shift( $your_name ) );
			$this->set_last_name( array_shift( $your_name ) );
		}

		$this->set_email_address(
			$submission->get_posted_string( 'your-email' ),
			'implicit'
		);

		$this->set_job_title(
			$submission->get_posted_string( 'your-job-title' )
		);

		$this->set_company_name(
			$submission->get_posted_string( 'your-company-name' )
		);

		$this->set_birthday(
			$submission->get_posted_string( 'your-birthday-month' ),
			$submission->get_posted_string( 'your-birthday-day' )
		);

		if ( ! ( $this->birthday_month && $this->birthday_day ) ) {
			$date = $submission->get_posted_string( 'your-birthday' );

			if ( preg_match( '/^(\d{4})-(\d{2})-(\d{2})$/', $date, $matches ) ) {
				$this->set_birthday( $matches[2], $matches[3] );
			}
		}

		$this->set_anniversary(
			$submission->get_posted_string( 'your-anniversary' )
		);

		$this->add_phone_number(
			$submission->get_posted_string( 'your-phone-number' )
		);

		$this->add_street_address(
			$submission->get_posted_string( 'your-address-street' ),
			$submission->get_posted_string( 'your-address-city' ),
			$submission->get_posted_string( 'your-address-state' ),
			$submission->get_posted_string( 'your-address-postal-code' ),
			$submission->get_posted_string( 'your-address-country' )
		);

		$service_option = (array) WPCF7::get_option( 'constant_contact' );

		$contact_lists = isset( $service_option['contact_lists'] )
			? $service_option['contact_lists'] : array();

		$contact_form = $submission->get_contact_form();

		$prop = $contact_form->prop( 'constant_contact' );

		if ( ! empty( $prop['enable_contact_list'] )
		and ! empty( $prop['contact_lists'] ) ) {
			foreach ( (array) $prop['contact_lists'] as $list_id ) {
				$this->add_list_membership( $list_id );
			}
		}
	}

	public function is_valid() {
		return $this->create_source
			&& ( $this->email_address || $this->first_name || $this->last_name );
	}

	public function to_array() {
		$output = array(
			'email_address' => $this->email_address,
			'first_name' => $this->first_name,
			'last_name' => $this->last_name,
			'job_title' => $this->job_title,
			'company_name' => $this->company_name,
			'create_source' => $this->create_source,
			'birthday_month' => $this->birthday_month,
			'birthday_day' => $this->birthday_day,
			'anniversary' => $this->anniversary,
			'custom_fields' => $this->custom_fields,
			'phone_numbers' => $this->phone_numbers,
			'street_addresses' => $this->street_addresses,
			'list_memberships' => $this->list_memberships,
		);

		return array_filter( $output );
	}

	public function get_email_address() {
		if ( isset( $this->email_address['address'] ) ) {
			return $this->email_address['address'];
		}

		return '';
	}

	public function set_email_address( $address, $permission_to_send = '' ) {
		if ( ! wpcf7_is_email( $address )
		or 80 < $this->strlen( $address ) ) {
			return false;
		}

		$types_of_permission = array(
			'implicit', 'explicit', 'deprecate', 'pending',
			'unsubscribe', 'temp_hold', 'not_set',
		);

		if ( ! in_array( $permission_to_send, $types_of_permission ) ) {
			$permission_to_send = 'implicit';
		}

		return $this->email_address = array(
			'address' => $address,
			'permission_to_send' => $permission_to_send,
		);
	}

	public function set_first_name( $first_name ) {
		$first_name = trim( $first_name );

		if ( empty( $first_name )
		or 50 < $this->strlen( $first_name ) ) {
			return false;
		}

		return $this->first_name = $first_name;
	}

	public function set_last_name( $last_name ) {
		$last_name = trim( $last_name );

		if ( empty( $last_name )
		or 50 < $this->strlen( $last_name ) ) {
			return false;
		}

		return $this->last_name = $last_name;
	}

	public function set_job_title( $job_title ) {
		$job_title = trim( $job_title );

		if ( empty( $job_title )
		or 50 < $this->strlen( $job_title ) ) {
			return false;
		}

		return $this->job_title = $job_title;
	}

	public function set_company_name( $company_name ) {
		$company_name = trim( $company_name );

		if ( empty( $company_name )
		or 50 < $this->strlen( $company_name ) ) {
			return false;
		}

		return $this->company_name = $company_name;
	}

	public function set_create_source( $create_source ) {
		if ( ! in_array( $create_source, array( 'Contact', 'Account' ) ) ) {
			return false;
		}

		return $this->create_source = $create_source;
	}

	public function set_birthday( $month, $day ) {
		$month = (int) $month;
		$day = (int) $day;

		if ( $month < 1 || 12 < $month
		or $day < 1 || 31 < $day ) {
			return false;
		}

		$this->birthday_month = $month;
		$this->birthday_day = $day;

		return array( $this->birthday_month, $this->birthday_day );
	}

	public function set_anniversary( $anniversary ) {
		$pattern = sprintf(
			'#^(%s)$#',
			implode( '|', array(
				'\d{1,2}/\d{1,2}/\d{4}',
				'\d{4}/\d{1,2}/\d{1,2}',
				'\d{4}-\d{1,2}-\d{1,2}',
				'\d{1,2}-\d{1,2}-\d{4}',
			) )
		);

		if ( ! preg_match( $pattern, $anniversary ) ) {
			return false;
		}

		return $this->anniversary = $anniversary;
	}

	public function add_custom_field( $custom_field_id, $value ) {
		$uuid_pattern = '/^[0-9a-f-]+$/i';

		$value = trim( $value );

		if ( 25 <= count( $this->custom_fields )
		or ! preg_match( $uuid_pattern, $custom_field_id )
		or 255 < $this->strlen( $value ) ) {
			return false;
		}

		return $this->custom_fields[] = array(
			'custom_field_id' => $custom_field_id,
			'value' => $value,
		);
	}

	public function add_phone_number( $phone_number, $kind = 'home' ) {
		$phone_number = trim( $phone_number );

		if ( empty( $phone_number )
		or ! wpcf7_is_tel( $phone_number )
		or 25 < $this->strlen( $phone_number )
		or 2 <= count( $this->phone_numbers )
		or ! in_array( $kind, array( 'home', 'work', 'other' ) ) ) {
			return false;
		}

		return $this->phone_numbers[] = array(
			'phone_number' => $phone_number,
			'kind' => $kind,
		);
	}

	public function add_street_address( $street, $city, $state, $postal_code, $country, $kind = 'home' ) {
		$street = trim( $street );
		$city = trim( $city );
		$state = trim( $state );
		$postal_code = trim( $postal_code );
		$country = trim( $country );

		if ( ! ( $street || $city || $state || $postal_code || $country )
		or 1 <= count( $this->street_addresses )
		or ! in_array( $kind, array( 'home', 'work', 'other' ) )
		or 255 < $this->strlen( $street )
		or 50 < $this->strlen( $city )
		or 50 < $this->strlen( $state )
		or 50 < $this->strlen( $postal_code )
		or 50 < $this->strlen( $country ) ) {
			return false;
		}

		return $this->street_addresses[] = array(
			'kind' => $kind,
			'street' => $street,
			'city' => $city,
			'state' => $state,
			'postal_code' => $postal_code,
			'country' => $country,
		);
	}

	public function add_list_membership( $list_id ) {
		$uuid_pattern = '/^[0-9a-f-]+$/i';

		if ( 50 <= count( $this->list_memberships )
		or ! preg_match( $uuid_pattern, $list_id ) ) {
			return false;
		}

		return $this->list_memberships[] = $list_id;
	}

	protected function strlen( $text ) {
		return wpcf7_count_code_units( $text );
	}

}
