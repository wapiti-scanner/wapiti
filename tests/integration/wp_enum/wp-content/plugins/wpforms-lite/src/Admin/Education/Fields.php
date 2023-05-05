<?php

namespace WPForms\Admin\Education;

/**
 * Fields data holder.
 *
 * @since 1.6.6
 */
class Fields {

	/**
	 * All fields data.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	protected $fields;

	/**
	 * All fields data.
	 *
	 * @since 1.6.6
	 *
	 * @return array All possible fields.
	 */
	private function get_all() {

		if ( ! empty( $this->fields ) ) {
			return $this->fields;
		}

		$this->fields = [
			[
				'icon'    => 'fa-phone',
				'name'    => esc_html__( 'Phone', 'wpforms-lite' ),
				'name_en' => 'Phone',
				'type'    => 'phone',
				'group'   => 'fancy',
				'order'   => '50',
			],
			[
				'icon'    => 'fa-map-marker',
				'name'    => esc_html__( 'Address', 'wpforms-lite' ),
				'name_en' => 'Address',
				'type'    => 'address',
				'group'   => 'fancy',
				'order'   => '70',
			],
			[
				'icon'    => 'fa-calendar-o',
				'name'    => esc_html__( 'Date / Time', 'wpforms-lite' ),
				'name_en' => 'Date / Time',
				'type'    => 'date-time',
				'group'   => 'fancy',
				'order'   => '80',
			],
			[
				'icon'    => 'fa-link',
				'name'    => esc_html__( 'Website / URL', 'wpforms-lite' ),
				'name_en' => 'Website / URL',
				'type'    => 'url',
				'group'   => 'fancy',
				'order'   => '90',
			],
			[
				'icon'    => 'fa-upload',
				'name'    => esc_html__( 'File Upload', 'wpforms-lite' ),
				'name_en' => 'File Upload',
				'type'    => 'file-upload',
				'group'   => 'fancy',
				'order'   => '100',
			],
			[
				'icon'    => 'fa-lock',
				'name'    => esc_html__( 'Password', 'wpforms-lite' ),
				'name_en' => 'Password',
				'type'    => 'password',
				'group'   => 'fancy',
				'order'   => '130',
			],
			[
				'icon'    => 'fa-pencil-square-o',
				'name'    => esc_html__( 'Rich Text', 'wpforms-lite' ),
				'name_en' => 'Rich Text',
				'type'    => 'richtext',
				'group'   => 'fancy',
				'order'   => '140',
			],
			[
				'icon'    => 'fa-columns',
				'name'    => esc_html__( 'Layout', 'wpforms-lite' ),
				'name_en' => 'Layout',
				'type'    => 'layout',
				'group'   => 'fancy',
				'order'   => '150',
			],
			[
				'icon'    => 'fa-files-o',
				'name'    => esc_html__( 'Page Break', 'wpforms-lite' ),
				'name_en' => 'Page Break',
				'type'    => 'pagebreak',
				'group'   => 'fancy',
				'order'   => '160',
			],
			[
				'icon'    => 'fa-arrows-h',
				'name'    => esc_html__( 'Section Divider', 'wpforms-lite' ),
				'name_en' => 'Section Divider',
				'type'    => 'divider',
				'group'   => 'fancy',
				'order'   => '170',
			],
			[
				'icon'    => 'fa-code',
				'name'    => esc_html__( 'HTML', 'wpforms-lite' ),
				'name_en' => 'HTML',
				'type'    => 'html',
				'group'   => 'fancy',
				'order'   => '180',
			],
			[
				'icon'    => 'fa-file-image-o',
				'name'    => esc_html__( 'Content', 'wpforms-lite' ),
				'name_en' => 'Content',
				'type'    => 'content',
				'group'   => 'fancy',
				'order'   => '181',
			],
			[
				'icon'    => 'fa-file-text-o',
				'name'    => esc_html__( 'Entry Preview', 'wpforms-lite' ),
				'name_en' => 'Entry Preview',
				'type'    => 'entry-preview',
				'group'   => 'fancy',
				'order'   => '190',
			],
			[
				'icon'    => 'fa-star',
				'name'    => esc_html__( 'Rating', 'wpforms-lite' ),
				'name_en' => 'Rating',
				'type'    => 'rating',
				'group'   => 'fancy',
				'order'   => '200',
			],
			[
				'icon'    => 'fa-eye-slash',
				'name'    => esc_html__( 'Hidden Field', 'wpforms-lite' ),
				'name_en' => 'Hidden Field',
				'type'    => 'hidden',
				'group'   => 'fancy',
				'order'   => '210',
			],
			[
				'icon'    => 'fa-question-circle',
				'name'    => esc_html__( 'Custom Captcha', 'wpforms-lite' ),
				'name_en' => 'Custom Captcha',
				'type'    => 'captcha',
				'group'   => 'fancy',
				'addon'   => 'wpforms-captcha',
				'order'   => '300',
			],
			[
				'icon'    => 'fa-pencil',
				'name'    => esc_html__( 'Signature', 'wpforms-lite' ),
				'name_en' => 'Signature',
				'type'    => 'signature',
				'group'   => 'fancy',
				'addon'   => 'wpforms-signatures',
				'order'   => '310',
			],
			[
				'icon'    => 'fa-ellipsis-h',
				'name'    => esc_html__( 'Likert Scale', 'wpforms-lite' ),
				'name_en' => 'Likert Scale',
				'type'    => 'likert_scale',
				'group'   => 'fancy',
				'addon'   => 'wpforms-surveys-polls',
				'order'   => '400',
			],
			[
				'icon'    => 'fa-tachometer',
				'name'    => esc_html__( 'Net Promoter Score', 'wpforms-lite' ),
				'name_en' => 'Net Promoter Score',
				'type'    => 'net_promoter_score',
				'group'   => 'fancy',
				'addon'   => 'wpforms-surveys-polls',
				'order'   => '410',
			],
			[
				'icon'    => 'fa-file-o',
				'name'    => esc_html__( 'Single Item', 'wpforms-lite' ),
				'name_en' => 'Single Item',
				'type'    => 'payment-single',
				'group'   => 'payment',
				'order'   => '1',
			],
			[
				'icon'    => 'fa-list-ul',
				'name'    => esc_html__( 'Multiple Items', 'wpforms-lite' ),
				'name_en' => 'Multiple Items',
				'type'    => 'payment-multiple',
				'group'   => 'payment',
				'order'   => '2',
			],
			[
				'icon'    => 'fa-check-square-o',
				'name'    => esc_html__( 'Checkbox Items', 'wpforms-lite' ),
				'name_en' => 'Checkbox Items',
				'type'    => 'payment-checkbox',
				'group'   => 'payment',
				'order'   => '3',
			],
			[
				'icon'    => 'fa-caret-square-o-down',
				'name'    => esc_html__( 'Dropdown Items', 'wpforms-lite' ),
				'name_en' => 'Dropdown Items',
				'type'    => 'payment-select',
				'group'   => 'payment',
				'order'   => '4',
			],
			[
				'icon'    => 'fa-credit-card',
				'name'    => esc_html__( 'Stripe Credit Card', 'wpforms-lite' ),
				'name_en' => 'Stripe Credit Card',
				'type'    => 'stripe-credit-card',
				'group'   => 'payment',
				'addon'   => 'wpforms-stripe',
				'order'   => '88',
			],
			[
				'icon'    => 'fa-credit-card',
				'name'    => esc_html__( 'PayPal Commerce', 'wpforms-lite' ),
				'name_en' => 'PayPal Commerce',
				'type'    => 'paypal-commerce',
				'group'   => 'payment',
				'addon'   => 'wpforms-paypal-commerce',
				'order'   => '89',
			],
			[
				'icon'    => 'fa-credit-card',
				'name'    => esc_html__( 'Square', 'wpforms-lite' ),
				'name_en' => 'Square',
				'type'    => 'square',
				'group'   => 'payment',
				'addon'   => 'wpforms-square',
				'order'   => '92',
			],
			[
				'icon'    => 'fa-credit-card',
				'name'    => esc_html__( 'Authorize.Net', 'wpforms-lite' ),
				'name_en' => 'Authorize.Net',
				'type'    => 'authorize_net',
				'group'   => 'payment',
				'addon'   => 'wpforms-authorize-net',
				'order'   => '95',
			],
			[
				'icon'    => 'fa-money',
				'name'    => esc_html__( 'Total', 'wpforms-lite' ),
				'name_en' => 'Total',
				'type'    => 'payment-total',
				'group'   => 'payment',
				'order'   => '110',
			],
		];

		$captcha = $this->get_captcha();

		if ( ! empty( $captcha ) ) {
			array_push( $this->fields, $captcha );
		}

		return $this->fields;
	}

	/**
	 * Get Captcha field data.
	 *
	 * @since 1.6.6
	 *
	 * @return array Captcha field data.
	 */
	private function get_captcha() {

		$captcha_settings = wpforms_get_captcha_settings();

		if ( empty( $captcha_settings['provider'] ) ) {
			return [];
		}

		$captcha = [
			'hcaptcha'  => [
				'name' => 'hCaptcha',
				'icon' => 'fa-question-circle-o',
			],
			'recaptcha' => [
				'name' => 'reCAPTCHA',
				'icon' => 'fa-google',
			],
			'turnstile' => [
				'name' => 'Turnstile',
				'icon' => 'fa-question-circle-o',
			],
		];

		if ( ! empty( $captcha_settings['site_key'] ) || ! empty( $captcha_settings['secret_key'] ) ) {
			$captcha_name = $captcha[ $captcha_settings['provider'] ]['name'];
			$captcha_icon = $captcha[ $captcha_settings['provider'] ]['icon'];
		} else {
			$captcha_name = 'CAPTCHA';
			$captcha_icon = 'fa-question-circle-o';
		}

		return [
			'icon'    => $captcha_icon,
			'name'    => $captcha_name,
			'name_en' => $captcha_name,
			'type'    => 'captcha_' . $captcha_settings['provider'],
			'group'   => 'standard',
			'order'   => 180,
			'class'   => 'not-draggable',
		];
	}

	/**
	 * Get filtered fields data.
	 *
	 * Usage:
	 *      get_filtered( [ 'group' => 'payment' ] )       - fields from the 'payment' group.
	 *      get_filtered( [ 'addon' => 'surveys-polls' ] ) - fields of the addon 'surveys-polls'.
	 *      get_filtered( [ 'type' => 'payment-total' ] )  - field 'payment-total'.
	 *
	 * @since 1.6.6
	 *
	 * @param array $args Arguments array.
	 *
	 * @return array Fields data filtered according to given arguments.
	 */
	private function get_filtered( $args = [] ) {

		$default_args = [
			'group' => '',
			'addon' => '',
			'type'  => '',
		];

		$args = array_filter( wp_parse_args( $args, $default_args ) );

		$fields          = $this->get_all();
		$filtered_fields = [];

		foreach ( $args as $prop => $prop_val ) {
			foreach ( $fields as $field ) {
				if ( ! empty( $field[ $prop ] ) && $field[ $prop ] === $prop_val ) {
					array_push( $filtered_fields, $field );
				}
			}
		}

		return $filtered_fields;
	}

	/**
	 * Get fields by group.
	 *
	 * @since 1.6.6
	 *
	 * @param string $group Fields group (standard, fancy or payment).
	 *
	 * @return array.
	 */
	public function get_by_group( $group ) {

		return $this->get_filtered( [ 'group' => $group ] );
	}

	/**
	 * Get fields by addon.
	 *
	 * @since 1.6.6
	 *
	 * @param string $addon Addon slug.
	 *
	 * @return array.
	 */
	public function get_by_addon( $addon ) {

		return $this->get_filtered( [ 'addon' => $addon ] );
	}

	/**
	 * Get field by type.
	 *
	 * @since 1.6.6
	 *
	 * @param string $type Field type.
	 *
	 * @return array Single field data. Empty array if field is not available.
	 */
	public function get_field( $type ) {

		$fields = $this->get_filtered( [ 'type' => $type ] );

		return ! empty( $fields[0] ) ? $fields[0] : [];
	}

	/**
	 * Set key value of each field (conditionally).
	 *
	 * @since 1.6.6
	 *
	 * @param array  $fields    Fields data.
	 * @param string $key       Key.
	 * @param string $value     Value.
	 * @param string $condition Condition.
	 *
	 * @return array Updated field data.
	 */
	public function set_values( $fields, $key, $value, $condition ) {

		if ( empty( $fields ) || empty( $key ) ) {
			return $fields;
		}

		foreach ( $fields as $f => $field ) {

			switch ( $condition ) {
				case 'empty':
					$fields[ $f ][ $key ] = empty( $field[ $key ] ) ? $value : $field[ $key ];
					break;

				default:
					$fields[ $f ][ $key ] = $value;
			}
		}

		return $fields;
	}
}
