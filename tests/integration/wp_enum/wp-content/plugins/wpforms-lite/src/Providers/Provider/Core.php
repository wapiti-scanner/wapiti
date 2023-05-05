<?php

namespace WPForms\Providers\Provider;

/**
 * Class Core stores the basic information about the provider.
 * It's also a Container to load single instances of requires classes.
 *
 * @since 1.4.7
 */
abstract class Core {

	/**
	 * Unique provider slug.
	 *
	 * @since 1.4.7
	 *
	 * @var string
	 */
	public $slug;

	/**
	 * Translatable provider name.
	 *
	 * @since 1.4.7
	 *
	 * @var string
	 */
	public $name;

	/**
	 * Custom provider icon (logo).
	 *
	 * @since 1.4.7
	 *
	 * @var string
	 */
	public $icon;

	/**
	 * Custom priority for a provider, that will affect loading/placement order.
	 *
	 * @since 1.4.8
	 *
	 * @var int
	 */
	const PRIORITY = 10;

	/**
	 * Get the instance of the class.
	 *
	 * @since 1.4.7
	 * @since 1.7.3 Compatibility with PHP 8.1
	 *
	 * @return Core
	 */
	public static function get_instance() {

		static $instance;

		$class = static::class;

		if ( empty( $instance[ $class ] ) ) {
			// Same as new static(), but allows avoiding "abstract class init" error.
			$instance[ $class ] = new $class();
		}

		return $instance[ $class ];
	}

	/**
	 * Core constructor.
	 *
	 * @since 1.4.7
	 *
	 * @param array $params Possible keys: slug*, name*, icon. * are required.
	 *
	 * @throws \UnexpectedValueException Provider class should define provider's "slug"/"name" params.
	 */
	public function __construct( array $params ) {

		// Define required provider properties.
		if ( ! empty( $params['slug'] ) ) {
			$this->slug = \sanitize_key( $params['slug'] );
		} else {
			throw new \UnexpectedValueException( 'Provider class should define a provider "slug" param in its constructor.' );
		}
		if ( ! empty( $params['name'] ) ) {
			$this->name = \sanitize_text_field( $params['name'] );
		} else {
			throw new \UnexpectedValueException( 'Provider class should define a provider "name" param in its constructor.' );
		}

		$this->icon = WPFORMS_PLUGIN_URL . 'assets/images/sullie.png';
		if ( ! empty( $params['icon'] ) ) {
			$this->icon = \esc_url_raw( $params['icon'] );
		}

	}

	/**
	 * Add to list of registered providers.
	 *
	 * @since 1.4.7
	 *
	 * @param array $providers Array of all active providers.
	 *
	 * @return array
	 */
	public function register_provider( array $providers ) {

		$providers[ $this->slug ] = $this->name;

		return $providers;
	}

	/**
	 * Provide an instance of the object, that should process the submitted entry.
	 * It will use data from an already saved entry to pass it further to a Provider.
	 *
	 * @since 1.4.7
	 *
	 * @return null|\WPForms\Providers\Provider\Process
	 */
	abstract public function get_process();

	/**
	 * Provide an instance of the object, that should display provider settings
	 * on Settings > Integrations page in admin area.
	 * If you don't want to display it (i.e. you don't need it), you can pass null here in your Core provider class.
	 *
	 * @since 1.4.7
	 *
	 * @return null|\WPForms\Providers\Provider\Settings\PageIntegrations
	 */
	abstract public function get_page_integrations();

	/**
	 * Provide an instance of the object, that should display provider settings in the Form Builder.
	 * If you don't want to display it (i.e. you don't need it), you can pass null here in your Core provider class.
	 *
	 * @since 1.4.7
	 *
	 * @return null|\WPForms\Providers\Provider\Settings\FormBuilder
	 */
	abstract public function get_form_builder();
}
