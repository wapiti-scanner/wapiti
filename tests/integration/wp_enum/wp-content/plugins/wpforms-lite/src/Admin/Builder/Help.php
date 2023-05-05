<?php

namespace WPForms\Admin\Builder;

/**
 * Form Builder Help Screen.
 *
 * @since 1.6.3
 */
class Help {

	/**
	 * Settings.
	 *
	 * @since 1.6.3
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Docs data.
	 *
	 * @since 1.6.4
	 *
	 * @var array
	 */
	private $docs;

	/**
	 * Initialize class.
	 *
	 * @since 1.6.3
	 */
	public function init() { // phpcs:ignore WPForms.PHP.HooksMethod.InvalidPlaceForAddingHooks

		// This should be here, otherwise scheduled task doesn't execute.
		add_action( 'wpforms_builder_help_cache_update', [ $this, 'update_docs' ] );

		// Terminate initialization if not in builder.
		if ( ! wpforms_is_admin_page( 'builder' ) ) {
			return;
		}

		$this->setup();
		$this->hooks();
	}

	/**
	 * Setup settings and other things.
	 *
	 * @since 1.6.3
	 */
	private function setup() {

		$upload_dir  = wpforms_upload_dir();
		$upload_path = ! empty( $upload_dir['path'] )
			? trailingslashit( wp_normalize_path( $upload_dir['path'] ) )
			: trailingslashit( WP_CONTENT_DIR ) . 'uploads/wpforms/';

		$this->settings = [

			// Remote source URL.
			'docs_remote_source' => 'https://wpforms.com/wp-content/docs.json',

			// Docs cache file (full path).
			'cache_file'         => $upload_path . 'cache/docs.json',

			/**
			 * Allow modifying Help Docs cache TTL (time to live).
			 *
			 * @since 1.6.3
			 *
			 * @param int $cache_ttl Cache TTL in seconds. Defaults to 1 week.
			 */
			'cache_ttl'          => (int) apply_filters( 'wpforms_admin_builder_help_cache_ttl', WEEK_IN_SECONDS ),

			// Static URLs.
			'docs_url'           => 'https://wpforms.com/docs/',
			'support_ticket_url' => 'https://wpforms.com/account/support/',
			'upgrade_url'        => 'https://wpforms.com/pricing/',
		];
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.3
	 */
	private function hooks() {

		add_action( 'wpforms_builder_enqueues', [ $this, 'enqueues' ] );
		add_action( 'wpforms_admin_page', [ $this, 'output' ], 20 );
	}

	/**
	 * Enqueue assets.
	 *
	 * @since 1.6.3
	 */
	public function enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-builder-help',
			WPFORMS_PLUGIN_URL . "assets/js/components/admin/builder/help{$min}.js",
			[ 'wpforms-builder' ],
			WPFORMS_VERSION,
			true
		);

		wp_localize_script(
			'wpforms-builder-help',
			'wpforms_builder_help',
			$this->get_localized_data()
		);
	}

	/**
	 * Get localized data.
	 *
	 * @since 1.6.3
	 *
	 * @return array Localized data.
	 */
	public function get_localized_data() {

		return [
			'docs'       => $this->get_docs(),
			'categories' => $this->get_categories(),
			'context'    => [
				'terms' => $this->get_context_terms(),
				'docs'  => $this->get_context_docs(),
			],
		];
	}

	/**
	 * Get docs from the cache.
	 *
	 * @since 1.6.3
	 *
	 * @return array Docs data.
	 */
	public function get_docs() {

		if ( is_file( $this->settings['cache_file'] ) && is_readable( $this->settings['cache_file'] ) ) {
			$docs = json_decode( file_get_contents( $this->settings['cache_file'] ), true );
		}

		clearstatcache();

		if (
			empty( $docs ) ||
			(int) filemtime( $this->settings['cache_file'] ) + $this->settings['cache_ttl'] < time()
		) {
			// This code should execute once when the method called the first time,
			// Next update_docs() should be executed by schedule.
			$docs = $this->update_docs();
		}

		// Store in class private variable for further use.
		$this->docs = ! empty( $docs ) ? $docs : [];

		return $this->docs;
	}

	/**
	 * Update docs cache with actual data retrieved from the remote source.
	 *
	 * @since 1.6.3
	 *
	 * @return array|boolean Updated docs data. Or false on error.
	 */
	public function update_docs() {

		// Unfortunately, we need to call setup() here for properly scheduled execution.
		$this->setup();

		$wpforms_key = 'lite';

		if ( wpforms()->is_pro() ) {
			$wpforms_key = wpforms_get_license_key();
		}

		$request = wp_remote_get(
			add_query_arg( 'tgm-updater-key', $wpforms_key, $this->settings['docs_remote_source'] ),
			[
				// Limit the processing time to half of the default PHP max execution time,
				// so users will have a chance to see the Form Builder even without the docs data.
				'timeout'    => 15,
				'user-agent' => wpforms_get_default_user_agent(),
			]
		);

		if ( is_wp_error( $request ) ) {
			return false;
		}

		$content   = wp_remote_retrieve_body( $request );
		$cache_dir = dirname( $this->settings['cache_file'] );

		// Check cache directory and create it if needed.
		if ( ! file_exists( $cache_dir ) || ! wp_is_writable( $cache_dir ) ) {
			wp_mkdir_p( $cache_dir );
			wpforms_create_upload_dir_htaccess_file();
			wpforms_create_index_html_file( $cache_dir );
		}

		// Attempt to decode the json data.
		$docs = json_decode( $content, true );

		// If the data successfully decoded to array we caching the content.
		if ( is_array( $docs ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents
			file_put_contents( $this->settings['cache_file'], $content );
		} else {
			$docs = [];
		}

		// Schedule recurring updates.
		$this->schedule_update_docs();

		return $docs;
	}

	/**
	 * Schedule docs updates.
	 *
	 * @since 1.6.3
	 */
	public function schedule_update_docs() {

		$tasks = wpforms()->get( 'tasks' );

		if ( $tasks->is_scheduled( 'wpforms_builder_help_cache_update' ) !== false ) {
			return;
		}

		$tasks->create( 'wpforms_builder_help_cache_update' )
			  ->recurring( time() + $this->settings['cache_ttl'], $this->settings['cache_ttl'] )
			  ->params()
			  ->register();
	}

	/**
	 * Get categories.
	 *
	 * @since 1.6.3
	 *
	 * @return array Categories data.
	 */
	public function get_categories() {

		return [
			'getting-started' => esc_html__( 'Getting Started', 'wpforms-lite' ),
			'functionality'   => esc_html__( 'Functionality', 'wpforms-lite' ),
			'fields'          => esc_html__( 'Fields', 'wpforms-lite' ),
			'addons'          => esc_html__( 'Addons', 'wpforms-lite' ),
			'payments'        => esc_html__( 'Payments', 'wpforms-lite' ),
			'entries'         => esc_html__( 'Entries', 'wpforms-lite' ),
			'styling'         => esc_html__( 'Styling', 'wpforms-lite' ),
			'extending'       => esc_html__( 'Extending', 'wpforms-lite' ),
		];
	}

	/**
	 * Get context search terms.
	 *
	 * @since 1.6.3
	 *
	 * @return array Search terms by context.
	 */
	public function get_context_terms() {

		return [
			'new_form'                                => 'add form',
			'setup'                                   => 'form template',
			'fields/add_fields'                       => 'add fields',
			'fields/field_options'                    => 'field options',
			'fields/field_options/text'               => 'single line text',
			'fields/field_options/textarea'           => 'paragraph text',
			'fields/field_options/number-slider'      => 'number slider',
			'fields/field_options/select'             => 'dropdown',
			'fields/field_options/radio'              => 'multiple choice',
			'fields/field_options/checkbox'           => 'checkboxes',
			'fields/field_options/gdpr-checkbox'      => 'gdpr agreement',
			'fields/field_options/email'              => 'email',
			'fields/field_options/address'            => 'address',
			'fields/field_options/url'                => 'website/url',
			'fields/field_options/name'               => 'name',
			'fields/field_options/hidden'             => 'hidden',
			'fields/field_options/html'               => 'html',
			'fields/field_options/content'            => 'content',
			'fields/field_options/pagebreak'          => 'page break',
			'fields/field_options/entry-preview'      => 'entry preview',
			'fields/field_options/password'           => 'password',
			'fields/field_options/date-time'          => 'date time',
			'fields/field_options/divider'            => 'section divider',
			'fields/field_options/phone'              => 'phone',
			'fields/field_options/number'             => 'numbers',
			'fields/field_options/file-upload'        => 'file upload',
			'fields/field_options/captcha'            => 'custom captcha',
			'fields/field_options/rating'             => 'rating',
			'fields/field_options/richtext'           => 'rich text',
			'fields/field_options/layout'             => 'layout',
			'fields/field_options/likert_scale'       => 'likert scale',
			'fields/field_options/payment-single'     => 'single item',
			'fields/field_options/payment-multiple'   => 'multiple items',
			'fields/field_options/payment-checkbox'   => 'checkbox items',
			'fields/field_options/payment-select'     => 'dropdown items',
			'fields/field_options/payment-total'      => 'total',
			'fields/field_options/paypal-commerce'    => 'paypal checkout',
			'fields/field_options/stripe-credit-card' => 'stripe credit card',
			'fields/field_options/authorize_net'      => 'authorize.net credit card',
			'fields/field_options/square'             => 'square credit card',
			'fields/field_options/signature'          => 'signature',
			'fields/field_options/net_promoter_score' => 'net promoter score',
			'settings/general'                        => 'settings',
			'settings/anti_spam'                      => 'spam',
			'settings/notifications'                  => 'notification emails',
			'settings/confirmation'                   => 'confirmation message',
			'settings/lead_forms'                     => 'lead forms',
			'settings/form_abandonment'               => 'form abandonment',
			'settings/post_submissions'               => 'post submissions',
			'settings/user_registration'              => 'user registration',
			'settings/surveys_polls'                  => 'surveys and polls',
			'settings/conversational_forms'           => 'conversational forms',
			'settings/form_locker'                    => 'form locker',
			'settings/form_pages'                     => 'form pages',
			'settings/save_resume'                    => 'save and resume',
			'settings/google_sheets'                  => 'google sheets',
			'settings/webhooks'                       => 'webhooks',
			'providers'                               => '',
			'providers/aweber'                        => 'aweber',
			'providers/activecampaign'                => 'activecampaign',
			'providers/campaign_monitor'              => 'campaign monitor',
			'providers/constant_contact'              => 'constant contact',
			'providers/drip'                          => 'drip',
			'providers/getresponse'                   => 'getresponse',
			'providers/getresponse_v3'                => 'getresponse',
			'providers/mailchimp'                     => 'mailchimp',
			'providers/mailchimpv3'                   => 'mailchimp',
			'providers/mailerlite'                    => 'mailerlite',
			'providers/zapier'                        => 'zapier',
			'providers/salesforce'                    => 'salesforce',
			'providers/sendinblue'                    => 'sendinblue',
			'providers/hubspot'                       => 'hubspot',
			'payments'                                => '',
			'payments/paypal_commerce'                => 'paypal commerce',
			'payments/paypal_standard'                => 'paypal standard',
			'payments/stripe'                         => 'stripe',
			'payments/authorize_net'                  => 'authorize.net',
			'payments/square'                         => 'square',
			'revisions'                               => 'revisions',
		];
	}

	/**
	 * Get context (recommended) docs links.
	 *
	 * @since 1.6.3
	 *
	 * @return array Docs links by search terms.
	 */
	public function get_context_docs_links() {

		return [
			'add form'                  => [
				'/docs/creating-first-form/',
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
				'/docs/how-to-customize-the-submit-button/',
			],
			'new form'                  => [
				'/docs/creating-first-form/',
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
				'/docs/how-to-customize-the-submit-button/',
			],
			'create form'               => [
				'/docs/creating-first-form/',
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
				'/docs/how-to-customize-the-submit-button/',
			],
			'form template'             => [
				'/docs/how-to-create-a-custom-form-template/',
			],
			'add fields'                => [
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
			],
			'recaptcha'                 => [
				'/docs/setup-captcha-wpforms/',
			],
			'spam'                      => [
				'/docs/how-to-prevent-spam-in-wpforms/',
				'/docs/setup-captcha-wpforms/',
				'/docs/how-to-install-and-use-custom-captcha-addon-in-wpforms/',
				'/docs/setting-up-akismet-anti-spam-protection/',
			],
			'fields'                    => [
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
			],
			'field options'             => [
				'/docs/how-to-customize-form-field-options/',
			],
			'field settings'            => [
				'/docs/how-to-customize-form-field-options/',
			],
			'conditional logic'         => [
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/setup-form-notification-wpforms/',
				'/docs/setup-form-confirmation-wpforms/',
			],
			'single line text'          => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
				'/docs/how-to-use-custom-input-masks/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'paragraph'                 => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'paragraph text'            => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'textarea'                  => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'input mask'                => [
				'/docs/how-to-use-custom-input-masks/',
			],
			'limit words'               => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
			],
			'limit characters'          => [
				'/docs/how-to-limit-words-or-characters-in-a-form-field/',
			],
			'style'                     => [
				'/docs/how-to-style-wpforms-with-custom-css-beginners-guide/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-add-custom-css-to-your-wpforms/',
			],
			'custom css'                => [
				'/docs/how-to-style-wpforms-with-custom-css-beginners-guide/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-add-custom-css-to-your-wpforms/',
			],
			'css'                       => [
				'/docs/how-to-style-wpforms-with-custom-css-beginners-guide/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-add-custom-css-to-your-wpforms/',
			],
			'dropdown'                  => [
				'/docs/how-to-allow-multiple-selections-to-a-dropdown-field-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'select'                    => [
				'/docs/how-to-allow-multiple-selections-to-a-dropdown-field-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'multiple options'          => [
				'/docs/how-to-allow-multiple-selections-to-a-dropdown-field-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'bulk add'                  => [
				'/docs/how-to-bulk-add-choices-for-multiple-choice-checkbox-and-dropdown-fields/',
			],
			'multiple columns'          => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
			],
			'columns'                   => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
			],
			'randomize'                 => [
				'/docs/how-to-randomize-checkbox-and-multiple-choice-options/',
			],
			'image choices'             => [
				'/docs/how-to-add-image-choices-to-fields/',
			],
			'icon choices'              => [
				'/docs/using-icon-choices/',
			],
			'multiple choice'           => [
				'/docs/how-to-bulk-add-choices-for-multiple-choice-checkbox-and-dropdown-fields/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
				'/docs/how-to-randomize-checkbox-and-multiple-choice-options/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'radio'                     => [
				'/docs/how-to-bulk-add-choices-for-multiple-choice-checkbox-and-dropdown-fields/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
				'/docs/how-to-randomize-checkbox-and-multiple-choice-options/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'checkboxes'                => [
				'/docs/how-to-bulk-add-choices-for-multiple-choice-checkbox-and-dropdown-fields/',
				'/docs/how-to-add-a-terms-of-service-checkbox-to-a-form/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
				'/docs/how-to-randomize-checkbox-and-multiple-choice-options/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'checkbox'                  => [
				'/docs/how-to-bulk-add-choices-for-multiple-choice-checkbox-and-dropdown-fields/',
				'/docs/how-to-add-a-terms-of-service-checkbox-to-a-form/',
				'/docs/how-to-create-a-multi-column-layout-for-radio-buttons-and-checkboxes/',
				'/docs/how-to-randomize-checkbox-and-multiple-choice-options/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'gdpr'                      => [
				'/docs/how-to-create-gdpr-compliant-forms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'gdpr agreement'            => [
				'/docs/how-to-create-gdpr-compliant-forms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'number slider'             => [
				'/docs/how-to-add-a-number-slider-field-to-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'range'                     => [
				'/docs/how-to-add-a-number-slider-field-to-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'email'                     => [
				'/docs/setup-form-notification-wpforms/',
				'/docs/how-to-create-conditional-form-notifications-in-wpforms/',
				'/docs/troubleshooting-email-notifications/',
				'/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'address'                   => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'field'                     => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'state'                     => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'province'                  => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'region'                    => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'city'                      => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'country'                   => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'zip code'                  => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'postal code'               => [
				'/docs/how-to-customize-the-address-field/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'hidden'                    => [
				'/docs/how-to-choose-the-right-form-field-for-your-forms/',
				'/docs/how-to-use-smart-tags-in-wpforms/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
			],
			'rating'                    => [
				'/docs/how-to-add-a-rating-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'star'                      => [
				'/docs/how-to-add-a-rating-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'rich text'                 => [
				'/docs/how-to-use-the-rich-text-field-in-wpforms/',
			],
			'wysiwyg'                   => [
				'/docs/how-to-use-the-rich-text-field-in-wpforms/',
			],
			'editor'                    => [
				'/docs/how-to-use-the-rich-text-field-in-wpforms/',
			],
			'rich editor'               => [
				'/docs/how-to-use-the-rich-text-field-in-wpforms/',
			],
			'layout'                    => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'two columns'               => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'three columns'             => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'four columns'              => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'fields horizontally'       => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'fields in a row'           => [
				'/docs/how-to-use-the-layout-field-in-wpforms/',
			],
			'page break'                => [
				'/docs/how-to-create-multi-page-forms-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'page'                      => [
				'/docs/how-to-create-multi-page-forms-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'entry preview'             => [
				'/docs/how-to-show-entry-previews-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'break'                     => [
				'/docs/how-to-create-multi-page-forms-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'multi-page'                => [
				'/docs/how-to-create-multi-page-forms-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'password'                  => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'name'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'first'                     => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'last'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'surname'                   => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'custom captcha'            => [
				'/docs/how-to-install-and-use-custom-captcha-addon-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'numbers'                   => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'website/url'               => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'website'                   => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'url'                       => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'html'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'content'                   => [
				'docs/using-the-content-field/',
			],
			'code'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'date/time'                 => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-customize-the-date-time-field-in-wpforms/',
			],
			'date'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-customize-the-date-time-field-in-wpforms/',
			],
			'time'                      => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-customize-the-date-time-field-in-wpforms/',
			],
			'calendar'                  => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
				'/docs/how-to-customize-the-date-time-field-in-wpforms/',
			],
			'section divider'           => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'section'                   => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'divider'                   => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'header'                    => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'phone'                     => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'telephone'                 => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'mobile'                    => [
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'file upload'               => [
				'/docs/a-complete-guide-to-the-file-upload-field/',
				'/docs/how-to-allow-additional-file-upload-types/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'file'                      => [
				'/docs/a-complete-guide-to-the-file-upload-field/',
				'/docs/how-to-allow-additional-file-upload-types/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'upload'                    => [
				'/docs/a-complete-guide-to-the-file-upload-field/',
				'/docs/how-to-allow-additional-file-upload-types/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'signature'                 => [
				'/docs/how-to-install-and-use-the-signature-addon-in-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'likert scale'              => [
				'/docs/how-to-add-a-likert-scale-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'likert'                    => [
				'/docs/how-to-add-a-likert-scale-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'scale'                     => [
				'/docs/how-to-add-a-likert-scale-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'net promoter score'        => [
				'/docs/how-to-add-a-net-promoter-score-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'net'                       => [
				'/docs/how-to-add-a-net-promoter-score-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'promoter'                  => [
				'/docs/how-to-add-a-net-promoter-score-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'score'                     => [
				'/docs/how-to-add-a-net-promoter-score-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'nps'                       => [
				'/docs/how-to-add-a-net-promoter-score-field-to-wpforms/',
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'payment'                   => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
			],
			'price'                     => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
			],
			'cost'                      => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
			],
			'single item'               => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'multiple items'            => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'checkbox items'            => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
				'/docs/how-to-add-image-choices-to-fields/',
				'/docs/using-icon-choices/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'dropdown items'            => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'total'                     => [
				'/docs/how-to-require-payment-total-with-a-wordpress-form/',
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/paypal-commerce-addon/',
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-create-a-donation-form-with-multiple-amounts/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
				'/docs/how-to-customize-the-style-of-individual-form-fields/',
			],
			'paypal checkout'           => [
				'/docs/paypal-commerce-addon/',
				'/docs/testing-payments-with-the-paypal-commerce-addon/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
			],
			'stripe credit card'        => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/how-to-test-stripe-payments-on-your-site/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
			],
			'authorize.net credit card' => [
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
			],
			'square credit card'        => [
				'/docs/how-to-install-and-use-the-square-addon-with-wpforms/',
				'/docs/how-to-test-square-payments-on-your-site/',
				'/docs/how-to-customize-form-field-options/',
				'/docs/how-to-use-conditional-logic-with-wpforms/',
			],
			'settings'                  => [
				'/docs/creating-first-form/',
				'/docs/setup-form-notification-wpforms/',
				'/docs/setup-form-confirmation-wpforms/',
			],
			'submit'                    => [
				'/docs/how-to-customize-the-submit-button/',
			],
			'button'                    => [
				'/docs/how-to-customize-the-submit-button/',
			],
			'dynamic population'        => [
				'/developers/how-to-enable-dynamic-field-population/',
			],
			'offline'                   => [
				'/docs/how-to-enable-ajax-form-submissions/',
			],
			'offline forms'             => [
				'/docs/how-to-enable-ajax-form-submissions/',
			],
			'notification'              => [
				'/docs/setup-form-notification-wpforms/',
				'/docs/how-to-create-conditional-form-notifications-in-wpforms/',
				'/docs/troubleshooting-email-notifications/',
				'/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/',
			],
			'notifications'             => [
				'/docs/setup-form-notification-wpforms/',
				'/docs/how-to-create-conditional-form-notifications-in-wpforms/',
				'/docs/troubleshooting-email-notifications/',
				'/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/',
			],
			'notification email'        => [
				'/docs/setup-form-notification-wpforms/',
				'/docs/how-to-create-conditional-form-notifications-in-wpforms/',
				'/docs/troubleshooting-email-notifications/',
				'/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/',
			],
			'notification emails'       => [
				'/docs/setup-form-notification-wpforms/',
				'/docs/how-to-create-conditional-form-notifications-in-wpforms/',
				'/docs/troubleshooting-email-notifications/',
				'/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/',
			],
			'confirmation'              => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'confirmation message'      => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'redirect'                  => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'go to url (redirect)'      => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'confirmation page'         => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'conditional confirmation'  => [
				'/docs/setup-form-confirmation-wpforms/',
				'/docs/how-to-create-conditional-form-confirmations/',
			],
			'lead forms'                => [
				'/docs/lead-forms-addon/',
			],
			'form abandonment'          => [
				'/docs/how-to-install-and-use-form-abandonment-with-wpforms/',
			],
			'abandonment'               => [
				'/docs/how-to-install-and-use-form-abandonment-with-wpforms/',
			],
			'abandon'                   => [
				'/docs/how-to-install-and-use-form-abandonment-with-wpforms/',
			],
			'lead capture'              => [
				'/docs/how-to-install-and-use-form-abandonment-with-wpforms/',
			],
			'post submissions'          => [
				'/docs/how-to-install-and-use-the-post-submissions-addon-in-wpforms/',
			],
			'guest post'                => [
				'/docs/how-to-install-and-use-the-post-submissions-addon-in-wpforms/',
			],
			'user submission'           => [
				'/docs/how-to-install-and-use-the-post-submissions-addon-in-wpforms/',
			],
			'blog'                      => [
				'/docs/how-to-install-and-use-the-post-submissions-addon-in-wpforms/',
			],
			'post'                      => [
				'/docs/how-to-install-and-use-the-post-submissions-addon-in-wpforms/',
			],
			'user registration'         => [
				'/docs/how-to-install-and-use-user-registration-addon-with-wpforms/',
				'/docs/how-to-set-up-custom-user-meta-fields/',
			],
			'register'                  => [
				'/docs/how-to-install-and-use-user-registration-addon-with-wpforms/',
				'/docs/how-to-set-up-custom-user-meta-fields/',
			],
			'registration'              => [
				'/docs/how-to-install-and-use-user-registration-addon-with-wpforms/',
				'/docs/how-to-set-up-custom-user-meta-fields/',
			],
			'user meta'                 => [
				'/docs/how-to-install-and-use-user-registration-addon-with-wpforms/',
				'/docs/how-to-set-up-custom-user-meta-fields/',
			],
			'user'                      => [
				'/docs/how-to-install-and-use-user-registration-addon-with-wpforms/',
				'/docs/how-to-set-up-custom-user-meta-fields/',
			],
			'surveys'                   => [
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
			],
			'polls'                     => [
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
			],
			'surveys and polls'         => [
				'/docs/how-to-install-and-use-the-surveys-and-polls-addon/',
			],
			'conversational forms'      => [
				'/docs/how-to-install-and-use-the-conversational-forms-addon/',
			],
			'conversational'            => [
				'/docs/how-to-install-and-use-the-conversational-forms-addon/',
			],
			'form locker'               => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'password protection'       => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'entry limit'               => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'scheduling'                => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'restrict access'           => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'limit'                     => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'schedule'                  => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'restrict'                  => [
				'/docs/how-to-install-and-use-the-form-locker-addon-in-wpforms/',
				'/developers/how-to-display-remaining-entry-limit-number/',
			],
			'form pages'                => [
				'/docs/how-to-install-and-use-the-form-pages-addon/',
			],
			'save'                      => [
				'/docs/how-to-install-and-use-the-save-and-resume-addon-with-wpforms/',
			],
			'resume'                    => [
				'/docs/how-to-install-and-use-the-save-and-resume-addon-with-wpforms/',
			],
			'continue'                  => [
				'/docs/how-to-install-and-use-the-save-and-resume-addon-with-wpforms/',
			],
			'save and resume'           => [
				'/docs/how-to-install-and-use-the-save-and-resume-addon-with-wpforms/',
			],
			'save and continue'         => [
				'/docs/how-to-install-and-use-the-save-and-resume-addon-with-wpforms/',
			],
			'webhooks'                  => [
				'/docs/how-to-install-and-use-the-webhooks-addon-with-wpforms/',
			],
			'aweber'                    => [
				'/docs/install-use-aweber-addon-wpforms/',
			],
			'campaign monitor'          => [
				'/docs/how-to-install-and-use-campaign-monitor-addon-with-wpforms/',
			],
			'constant contact'          => [
				'/docs/how-to-connect-constant-contact-with-wpforms/',
			],
			'drip'                      => [
				'/docs/how-to-install-and-use-the-drip-addon-in-wpforms/',
			],
			'getresponse'               => [
				'/docs/how-to-install-and-use-getresponse-addon-with-wpforms/',
			],
			'google sheets'             => [
				'/docs/google-sheets-addon/',
				'/docs/google-permissions/',
			],
			'mailchimp'                 => [
				'/docs/install-use-mailchimp-addon-wpforms/',
			],
			'mailerlite'                => [
				'/docs/install-use-mailerlite-addon-wpforms/',
			],
			'zapier'                    => [
				'/docs/how-to-install-and-use-zapier-addon-with-wpforms/',
			],
			'salesforce'                => [
				'/docs/how-to-install-and-use-the-salesforce-addon-with-wpforms/',
			],
			'sendinblue'                => [
				'/docs/how-to-install-and-use-the-sendinblue-addon-with-wpforms/',
			],
			'hubspot'                   => [
				'/docs/how-to-install-and-use-the-hubspot-addon-in-wpforms/',
			],
			'integrate'                 => [
				'/docs/how-to-install-and-use-zapier-addon-with-wpforms/',
				'/docs/how-to-install-and-use-the-webhooks-addon-with-wpforms/',
				'/docs/google-sheets-addon/',
			],
			'integration'               => [
				'/docs/how-to-install-and-use-zapier-addon-with-wpforms/',
				'/docs/how-to-install-and-use-the-webhooks-addon-with-wpforms/',
				'/docs/google-sheets-addon/',
			],
			'crm'                       => [
				'/docs/how-to-install-and-use-zapier-addon-with-wpforms/',
				'/docs/how-to-install-and-use-the-webhooks-addon-with-wpforms/',
			],
			'api'                       => [
				'/docs/how-to-install-and-use-zapier-addon-with-wpforms/',
				'/docs/how-to-install-and-use-the-webhooks-addon-with-wpforms/',
				'/docs/google-sheets-addon/',
			],
			'paypal commerce'           => [
				'/docs/paypal-commerce-addon/',
				'/docs/testing-payments-with-the-paypal-commerce-addon/',
			],
			'paypal standard'           => [
				'/docs/install-use-paypal-addon-wpforms/',
				'/docs/how-to-test-paypal-payments-before-accepting-real-payments/',
				'/docs/how-to-allow-users-to-choose-a-payment-method-on-your-form/',
			],
			'stripe'                    => [
				'/docs/how-to-install-and-use-the-stripe-addon-with-wpforms/',
				'/docs/how-to-test-stripe-payments-on-your-site/',
			],
			'authorize'                 => [
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
			],
			'authorize.net'             => [
				'/docs/how-to-install-and-use-the-authorize-net-addon-with-wpforms/',
			],
			'square'                    => [
				'/docs/how-to-install-and-use-the-square-addon-with-wpforms/',
				'/docs/how-to-test-square-payments-on-your-site/',
			],
			'revisions'                 => [
				'/docs/how-to-use-form-revisions-in-wpforms/',
			],
		];
	}

	/**
	 * Get context (recommended) docs.
	 *
	 * @since 1.6.3
	 *
	 * @return array Docs recommended by search terms.
	 */
	public function get_context_docs() {

		if ( empty( $this->docs ) ) {
			return [];
		}

		$docs_links = $this->get_context_docs_links();
		$docs       = [];

		foreach ( $docs_links as $word => $links ) {
			$docs[ $word ] = $this->get_doc_ids( $links );
		}

		return $docs;
	}

	/**
	 * Get doc id.
	 *
	 * @since 1.6.3
	 *
	 * @param string $link Absolute link to the doc without the domain part.
	 *
	 * @return array Array with doc id as element.
	 */
	public function get_doc_id( $link ) {

		if ( empty( $this->docs ) ) {
			return [];
		}

		$result = array_filter(
			$this->docs,
			static function( $doc ) use ( $link ) {

				return ! empty( $doc['url'] ) && $doc['url'] === 'https://wpforms.com' . $link;
			}
		);

		return ! empty( $result ) && is_array( $result ) ? array_keys( $result ) : [];
	}

	/**
	 * Get doc ids.
	 *
	 * @since 1.6.3
	 *
	 * @param array $links Array of the doc links.
	 *
	 * @return array Doc ids.
	 */
	public function get_doc_ids( $links ) {

		if ( empty( $this->docs ) ) {
			return [];
		}

		$ids = [];

		foreach ( $links as $link ) {
			$ids = array_merge( $ids, $this->get_doc_id( $link ) );
		}

		return $ids;
	}

	/**
	 * Output help modal markup.
	 *
	 * @since 1.6.3
	 */
	public function output() {

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'builder/help',
			[
				'settings' => $this->settings,
			],
			true
		);
	}
}
